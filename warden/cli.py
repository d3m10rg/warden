"""Passive collector and explicit on-demand diagnostics."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import time

from . import __version__
from .core import DEFAULTS, RETENTION, STALE_SECONDS, config
from .linux import JournalPoller, collect
from .storage import Store, history, latest, traffic


def duration(value):
    try:
        units = {"s": 1, "m": 60, "h": 3600}
        seconds = float(value[:-1]) * units[value[-1]]
        if not 0 < seconds <= RETENTION:
            raise ValueError()
        return seconds
    except (ValueError, KeyError, IndexError):
        raise argparse.ArgumentTypeError("Use 1m, 1h, 24h, etc. Maximum: 48h") from None


def parser():
    root = argparse.ArgumentParser(description="Warden — VPN observations and bounded on-demand diagnostics")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--config", default="/etc/warden/config.json")
    root.add_argument("--database", help="Override Warden history path")
    root.add_argument("--demo", action="store_true", help="Synthetic data; no host inspection")
    sub = root.add_subparsers(dest="command")
    for name in ("status", "list", "show", "traffic", "history", "tui", "collect"):
        cmd = sub.add_parser(name)
        if name not in ("tui", "collect"):
            cmd.add_argument("--json", action="store_true")
        if name in ("status", "list", "show"):
            cmd.add_argument("--live", action="store_true", help="Read host directly; do not write history")
        if name in ("show", "traffic"):
            cmd.add_argument("entity", help="Channel/interface ID, or ID/peer_id")
        if name == "history":
            cmd.add_argument("entity", nargs="?")
            cmd.add_argument("--since", type=duration, default=RETENTION)
        if name == "traffic":
            cmd.add_argument("--window", type=duration, default=3600)
        if name == "collect":
            cmd.add_argument("--once", action="store_true")
    doc = sub.add_parser("doctor", help="Passive allowlisted report, without addresses or credentials")
    doc.add_argument("--json", action="store_true")
    for name in ("ping", "https", "speed"):
        cmd = sub.add_parser(name, help="Preview diagnostic; --run explicitly sends traffic")
        cmd.add_argument("entity", help="Tunnel ID")
        cmd.add_argument("--json", action="store_true")
        cmd.add_argument("--run", action="store_true")
        cmd.add_argument("--expect-plan", help=argparse.SUPPRESS)
        if name == "ping":
            cmd.add_argument("--scope", choices=("internal", "external"), default="internal")
        if name == "speed":
            cmd.add_argument("--seconds", type=int, choices=range(1, 11), default=5)
            cmd.add_argument("--mbps", type=int, choices=range(1, 11), default=5)
            cmd.add_argument("--reverse", action="store_true", help="Download instead of upload")
    return root


def demo():
    now = time.time()
    tunnel = {"id": "secondary", "interface": "awgfp0", "name": "Forpost2 (demo)", "kind": "Failover member",
              "role": "Active", "health": "Healthy", "reason": "Synthetic successful HTTPS probe", "note": "Demo only",
              "enabled": True, "rank": None, "rx": 3000000, "tx": 900000, "rx_bps": 1250000, "tx_bps": 420000,
              "healthy_observed_seconds": 120, "active_observed_seconds": 120,
              "generation": "demo", "peers": [{"peer_id": "demo-peer", "name": "10.90.0.1/32",
              "health": "Recent handshake", "handshake_age_seconds": 20, "handshake": int(now)-20,
              "endpoint": "192.0.2.20:51889", "allowed_ips": ["0.0.0.0/0"], "rx": 2900000,
              "tx": 890000, "generation": "demo", "rx_bps": 1200000, "tx_bps": 400000}]}
    return {"schema_version": 1, "warden_version": __version__, "timestamp": now, "monotonic": time.monotonic(),
            "boot": "demo", "duration_seconds": 0, "controller": {"active": "secondary", "reported_active": "secondary",
            "version": "controller-v1", "fresh": True, "age_seconds": 2, "unreachable_guard": True, "local_source_rule": True},
            "tunnels": [tunnel, dict(tunnel, id="primary", name="Forpost (demo)", interface="awgfp1",
                role="None", health="Down", reason="Synthetic failed HTTPS probes", peers=[], rx_bps=0, tx_bps=0)],
            "services": [{"id": "sing-box-vless-ws.service", "state": "Running"}, {"id": "nginx.service", "state": "Running"}],
            "vless": {"users": 2, "client_session": "Not tested", "listeners": [{"address": "127.0.0.1", "port": 10000, "listening": True}]},
            "warnings": ["DEMO: synthetic data; no commands executed"]}


def snapshot(cfg, live=False):
    problem = None
    if not live:
        try:
            data = latest(cfg["database"])
            if data:
                return data
        except (OSError, ValueError, sqlite3.Error):
            problem = "History unavailable; showing a live observation"
    data = collect(cfg)
    data["warnings"].append(problem or "Live observation; rates and observed uptime require the collector")
    return data


@contextlib.contextmanager
def collector_lock(path):
    import fcntl
    lockpath = Path(path).with_suffix(".lock")
    lockpath.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with lockpath.open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Warden collector already running; no second writer started") from None
        yield


def collector(cfg, once=False):
    if sys.platform != "linux":
        raise ValueError("Collector requires Linux")
    os.umask(0o077)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    with collector_lock(cfg["database"]):
        store = Store(cfg["database"])
        journal = JournalPoller()
        try:
            while not stopping:
                start = time.monotonic()
                data = collect(cfg)
                # Rebuild up to 48h once after upgrading the old reverse reader.
                forward = store.get("journal_reader_version") == 2
                cursor = store.get("journal_cursor") if forward else None
                since = store.get("journal_since") if forward else None
                events, new_cursor, watermark = journal.poll(cursor, since)
                data["journal"] = dict(journal.info)
                warning = journal.warning()
                if warning:
                    data["warnings"].append(warning)
                store.save(data, events, new_cursor, watermark)
                if once:
                    print("Collected one observation into " + str(cfg["database"]))
                    break
                # Interruptible sleep; no catch-up burst after a slow collection.
                deadline = time.monotonic() + max(1, 10 - (time.monotonic() - start))
                while not stopping and time.monotonic() < deadline:
                    time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        finally:
            store.close()


def find_entity(data, key):
    from .storage import entities
    for name, row in entities(data):
        if name == key:
            return row
    raise ValueError("Unknown entity; use warden list or warden show <tunnel>")


def main(argv=None):
    args_list = list(sys.argv[1:] if argv is None else argv)
    args_list = [{"-status": "status", "-list": "list"}.get(a, a) for a in args_list]
    args = parser().parse_args(args_list)
    try:
        cfg = dict(DEFAULTS) if args.demo else config(args.config)
        if args.database:
            cfg["database"] = str(Path(args.database).resolve())
        name = args.command or ("tui" if sys.stdin.isatty() and sys.stdout.isatty() else "status")
        if args.demo and name in ("collect", "traffic", "history", "ping", "https", "speed", "doctor"):
            raise ValueError("Demo supports status/list/show/TUI only")
        if name in ("ping", "https", "speed", "doctor"):
            from .diagnostics import diagnostic_lock, doctor, execute, format_result, plan
            if sys.platform != "linux":
                raise ValueError("Host diagnostics require Linux")
            if name == "doctor":
                try:
                    recorded = latest(cfg["database"])
                except (OSError, ValueError, sqlite3.Error):
                    recorded = None
                result = doctor(collect(cfg), recorded)
            else:
                # SIGTERM from TUI must unwind subprocess/socket cleanup too.
                def cancel(*_):
                    raise KeyboardInterrupt()
                signal.signal(signal.SIGTERM, cancel)
                with diagnostic_lock():
                    data = collect(cfg)
                    p = plan(data, cfg, args.entity, args.scope if name == "ping" else name,
                             getattr(args, "seconds", 5), getattr(args, "mbps", 5), getattr(args, "reverse", False))
                    if args.expect_plan:
                        expected = json.loads(args.expect_plan)
                        if {k: v for k, v in p.items() if k != "timestamp"} != expected:
                            raise ValueError("Diagnostic target/route changed; preview again before execution")
                    result = execute(p) if args.run else p
            if args.json or name == "doctor":
                print(json.dumps(result, ensure_ascii=True, indent=2))
            else:
                print("\n".join(format_result(result)))
            return 1 if result.get("status") in ("Failed", "Error", "Timeout", "No reply") else 0
        if name == "collect":
            collector(cfg, args.once)
            return 0
        if name in ("traffic", "history"):
            if not Path(cfg["database"]).is_file():
                raise ValueError("No history yet; install/start warden-collector or run collect --once")
            now = time.time()
            result = traffic(cfg["database"], args.entity, now, args.window) if name == "traffic" else history(cfg["database"], now - args.since, args.entity)
            if getattr(args, "json", False):
                print(json.dumps({"schema_version": 1, "data": result}, ensure_ascii=True, indent=2))
            else:
                from .tui import format_history, format_traffic
                print("\n".join(format_traffic(result) if name == "traffic" else format_history(result)))
            return 0
        data = demo() if args.demo else snapshot(cfg, getattr(args, "live", False))
        if name == "tui":
            from .tui import run
            run(data, cfg, demo_mode=args.demo, config_path=args.config)
            return 0
        if name == "show":
            result = find_entity(data, args.entity)
        else:
            result = data if name == "status" else data["tunnels"]
        if getattr(args, "json", False):
            age = time.time() - data["timestamp"]
            print(json.dumps({"schema_version": 1, "age_seconds": round(age, 2),
                              "stale": not 0 <= age <= STALE_SECONDS, "data": result}, ensure_ascii=True, indent=2))
        else:
            from .tui import overview
            if name == "show":
                print(json.dumps(result, ensure_ascii=True, indent=2))
            else:
                print("\n".join(overview(data)))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        # Config parsing/OS errors may contain raw input; report type, not secrets.
        text = str(exc) if type(exc) is ValueError and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__ + ": unable to read data; check paths/permissions"
        print("warden: " + text, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
