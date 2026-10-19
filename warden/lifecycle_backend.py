"""Stop/start one Maintenance channel through the installed transaction journal."""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import signal
import sys
import time

if __package__:
    from .maintenance_backend import guard, load_backend
else:
    from maintenance_backend import guard, load_backend

STOP_DIR = Path("/etc/warden/stopped")
UNIT_DIR = Path("/etc/systemd/system")
RESET_WINDOW = 90
PROPERTIES = ("Id", "LoadState", "ActiveState", "Requires", "Wants", "RequiredBy", "BoundBy",
              "PartOf", "BindsTo", "ConsistsOf", "Conflicts", "PropagatesStopTo", "StopWhenUnneeded",
              "FragmentPath", "DropInPaths")


def digest(content):
    return hashlib.sha256(content).hexdigest()


def secure(p, path):
    # Check ancestors too: neither symlink redirection nor writable drop-in dirs.
    for part in (path, *path.parents):
        p.require(not part.is_symlink(), "Symlink in lifecycle state/config path")
        if part.exists():
            st = part.stat()
            p.require(st.st_uid == 0 and not st.st_mode & 0o022, "Unsafe lifecycle state/config ownership")


def units(p, c):
    p.require(re.fullmatch(r"awgfp[0-9]+", c["if"]), "Only registered awgfp interfaces support Stop/Start")
    kind = (c.get("transport") or {}).get("kind", "udp")
    p.require(kind in ("icmp", "faketcp", "wss"), "Stop/Start requires a known ICMP/fakeTCP/WSS transport")
    return ["awg-quick@" + c["if"] + ".service",
            ("forpost-wss-" if kind == "wss" else "forpost-faketcp-") + c["if"] + ".service"]


def unit_state(p, unit):
    result = p.run(["systemctl", "show", unit, "--no-pager"] + ["--property=" + k for k in PROPERTIES])
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def inventory(p, c, group, stopping, marker):
    config = p.AWG_DIR / (c["if"] + ".conf")
    secure(p, config)
    profile = p.parse_awg(p.secure_file(config).read_text())["Interface"]
    p.require(profile.get("Table", "").lower() == "off" and
              profile.get("SaveConfig", "false").lower() == "false" and
              not any(k in profile for k in ("PreUp", "PostUp", "PreDown", "PostDown", "DNS")),
              "Stop/Start requires Table=off without SaveConfig, DNS or AWG hooks; inspect profile locally")
    hashes = {str(config): digest(config.read_bytes())}
    for unit in group:
        state = unit_state(p, unit)
        p.require(state.get("Id") == unit and state.get("LoadState") == "loaded", "Managed unit unavailable")
        p.require(state.get("ActiveState") == ("active" if stopping else "inactive"),
                  "Unit state differs from expected active/stopped state: " + unit)
        p.require(state.get("StopWhenUnneeded") == "no", "StopWhenUnneeded is unsupported")
        for key in ("Requires", "Wants", "RequiredBy", "BoundBy", "PartOf", "BindsTo", "ConsistsOf",
                    "Conflicts", "PropagatesStopTo"):
            edges = shlex.split(state.get(key, ""))
            p.require(all(not e.endswith(".service") or e in group for e in edges),
                      "Foreign service dependency in " + key + " for " + unit)
        owned = UNIT_DIR / (unit + ".d") / "90-warden-stop.conf"
        for name in [state.get("FragmentPath", "")] + shlex.split(state.get("DropInPaths", "")):
            p.require(bool(name) and Path(name).is_absolute(), "Unit source path unavailable")
            path = Path(name)
            secure(p, path)
            if path != owned:
                hashes[str(path)] = digest(path.read_bytes())
        secure(p, owned)
        content = ("[Unit]\nConditionPathExists=!" + str(marker) + "\n").encode()
        p.require(not owned.exists() or owned.read_bytes() == content, "Warden stop drop-in differs; inspect before changing")
        if not stopping:
            p.require(owned.exists() and owned in [Path(n) for n in shlex.split(state.get("DropInPaths", ""))],
                      "Persistent stop drop-in missing or not loaded")
    return hashes


def route_commands(p, c):
    """Accept only the three canonical link-dependent routes; never replace foreign routes."""
    commands = []
    for table in (10400, c["table"]):
        for r in p.routes(table):
            if r.get("dev") != c["if"]:
                continue
            peer = r.get("dst") in (c["peer"], c["peer"] + "/32")
            default = table == c["table"] and r.get("dst") == "default" and r.get("gateway") == c["peer"]
            p.require((peer and r.get("scope") == "link" and not r.get("gateway") and not r.get("metric")) or
                      (default and r.get("metric") == 100), "Unexpected channel route; inspect before Stop/Start")
            p.require(set(r) <= {"dst", "dev", "scope", "protocol", "flags", "table", "type", "gateway", "metric"}
                      and r.get("type", "unicast") == "unicast" and r.get("protocol", "boot") == "boot"
                      and set(r.get("flags", [])) <= {"onlink"}, "Custom channel route attributes unsupported")
            commands.append((["ip", "-4", "route", "replace", c["peer"] + "/32", "dev", c["if"],
                              "scope", "link", "table", str(table)]) if peer else p.expected_default(c, table))
    expected = [["ip", "-4", "route", "replace", c["peer"] + "/32", "dev", c["if"], "scope", "link", "table", str(t)]
                for t in (10400, c["table"])] + [p.expected_default(c, c["table"])]
    p.require(len(commands) == len(expected) and all(cmd in commands for cmd in expected),
              "Channel probe routes incomplete; restore routing before Stop")
    return expected


def wait_for_https(ctl, c, active):
    p = ctl.p
    deadline = time.monotonic() + RESET_WINDOW
    ctl.say("WAIT", "Client AWG/transport ready. In the selected Forpost console restart ONLY its udp2raw transport now; "
            "leave server AWG and this Ravelin session running. Up to 90s for HTTPS 3/3.")
    while True:
        p.require(p.active_route() == active, "Active exit changed during startup wait")
        guard(p)
        results, details = [], []
        for target in p.TARGETS:
            if time.monotonic() >= deadline:
                results.append(False)
                continue
            observed = {}
            results.append(p.probe_one(c, target, deadline=min(deadline, time.monotonic() + 5), observation=observed))
            # Project fixed fields only; no exception/config/credential text.
            details.append({k: observed[k] for k in ("target", "stage", "reason", "elapsed_ms") if k in observed})
        ctl.say("CHECK", "HTTPS " + c["id"] + ": " + json.dumps(results) + "; probes=" + json.dumps(details))
        p.require(p.active_route() == active, "Active exit changed during startup wait")
        if len(results) == 3 and all(results):
            return
        remaining = deadline - time.monotonic()
        p.require(remaining > 0, "ICMP startup HTTPS acceptance failed after server-reset wait; rolling back to Stopped")
        time.sleep(min(2, remaining))


def lifecycle(ctl, args):
    p = ctl.p
    for name in ("probe_reply_change",):
        p.require(callable(getattr(ctl, name, None)), "Installed lifecycle API unsupported")
    stopping = args.action == "stop"
    with p.locked(wait_seconds=30):
        p.require(digest(p.CHANNELS.read_bytes()) == args.expected, "Registry changed since preview; preview again")
        data = ctl.registry()
        c = next((c for c in data["channels"] if c["id"] == args.id), None)
        p.require(c is not None and not c.get("retired") and not c["enabled"] and c.get("maintenance") is True,
                  "Stop/Start requires a non-retired channel already in Maintenance")
        p.require(c.get("stopped", False) is (not stopping), "Channel stopped state changed; preview again")
        group = units(p, c)
        coordinated = not stopping and c["transport"]["kind"] == "icmp"
        wait = getattr(args, "wait_for_server_reset", False)
        p.require(not coordinated or wait, "ICMP Start requires --wait-for-server-reset and a ready Forpost console; no changes made")
        p.require(not wait or coordinated, "Server-reset wait is supported only for ICMP Start")
        if coordinated:
            p.require(len(p.TARGETS) == 3, "Expected three backend HTTPS targets")
            # Refuse older API before opening a transaction or starting services.
            try:
                inspect.signature(p.probe_one).bind(c, p.TARGETS[0], deadline=0, observation={})
            except TypeError:
                raise ValueError("Installed probe API lacks bounded startup diagnostics; no changes made") from None
        marker = STOP_DIR / c["if"]
        secure(p, marker)
        p.require(marker.exists() is (not stopping), "Persistent stop marker missing or unexpected")
        hashes = inventory(p, c, group, stopping, marker)
        identity = {k: v for k, v in c.items() if k != "stopped"}
        saved = {"version": 1, "channel": identity, "files": hashes}
        if not stopping:
            saved = json.loads(p.secure_file(marker).read_text())
            p.require(saved.get("version") == 1 and saved.get("channel") == identity and saved.get("files") == hashes,
                      "Channel/config/unit changed since Stop; inspect before Start")
        guard(p)
        p.require(p.active_route() not in ("none", c["id"]), "A different active exit is required")
        with ctl.change("ravelin", args) as tx:
            active = p.active_route()
            healthy, _ = p.probe_paths()
            p.require(healthy.get(active) is True, "Current alternative exit is unhealthy; Stop/Start refused")
            if stopping:
                p.require(p.interface_exists(c["if"]) and p.address_on(c["if"], c["local"]), "Channel interface/address unavailable")
                restore = route_commands(p, c)
                key = p.probe_src_valid_mark(c)
                value = p.out("sysctl", "-n", key).strip()
                p.require(value == "1" and p.probe_reply_present(c), "Probe reply protection missing")
                # This inverse runs AFTER transport and AWG have restarted during rollback.
                tx.command(["true"], [["sysctl", "-q", "-w", key + "=1"]] + restore)
                for unit in group:  # AWG first, then its transport.
                    tx.command(["systemctl", "stop", unit], [["systemctl", "start", unit]])
                for unit in group:
                    tx.file(UNIT_DIR / (unit + ".d") / "90-warden-stop.conf",
                            ("[Unit]\nConditionPathExists=!" + str(marker) + "\n").encode(), 0o644)
                tx.file(marker, ctl.encode(saved))
                tx.command(["systemctl", "daemon-reload"], [["systemctl", "daemon-reload"]])
            else:
                tx.delete_file(marker)
                tx.command(["systemctl", "daemon-reload"], [["systemctl", "daemon-reload"]])
                for unit in reversed(group):
                    tx.command(["systemctl", "start", unit], [["systemctl", "stop", unit]])
                p.require(p.interface_exists(c["if"]) and p.address_on(c["if"], c["local"]), "Started interface/address unavailable")
                # Rules, nft tables and unreachable defaults survive link removal.
                p.require(p.probe_reply_present(c) and any(p.rule_matches(r, c) for r in p.jrun("ip", "-j", "-4", "rule", "show")),
                          "Probe rules changed while stopped; inspect routing first")
                p.require(any(r.get("type") == "unreachable" and r.get("dst") == "default" and r.get("metric") == 42760
                              for r in p.routes(c["table"])), "Probe unreachable guard missing")
                for table in (10400, c["table"]):
                    p.require(not any(r.get("dev") == c["if"] for r in p.routes(table)), "Unexpected routes after Start")
                    p.require(not any(r.get("dst") in (c["peer"], c["peer"] + "/32") for r in p.routes(table)), "Peer route conflict after Start")
                    if table == c["table"]:
                        p.require(all(r.get("type") == "unreachable" and r.get("dst") == "default"
                                      for r in p.routes(table)), "Foreign probe route; Start refused")
                    tx.command(["ip", "-4", "route", "add", c["peer"] + "/32", "dev", c["if"], "scope", "link", "table", str(table)],
                               [["ip", "-4", "route", "del", c["peer"] + "/32", "dev", c["if"], "table", str(table)]])
                tx.command(p.expected_default(c, c["table"]), [p.delete_default(c, c["table"])])
                ctl.probe_reply_change(tx, c)
                if coordinated:
                    wait_for_https(ctl, c, active)
                else:
                    ctl.probe_candidate(c)
            p.require(p.interface_exists(c["if"]) is (not stopping), "Interface state did not change as expected")
            for unit in group:
                p.require(unit_state(p, unit).get("ActiveState") == ("inactive" if stopping else "active"), "Unit transition incomplete")
            for name, sha in hashes.items():
                p.require(digest(Path(name).read_bytes()) == sha, "Config/unit changed during operation")
            c["stopped"] = stopping
            p.validate_channels(data)
            tx.file(p.CHANNELS, ctl.encode(data))
            p.load_channels()
            guard(p)
            p.require(p.active_route() == active, "Active exit changed unexpectedly")
            ctl.verify_vless()
        ctl.say("OK", args.action.capitalize() + ": " + args.id + "; channel remains in Maintenance")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--action", choices=("stop", "start"), required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--wait-for-server-reset", action="store_true")
    args = parser.parse_args()
    args.ssh_client, args.console = None, False
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Lifecycle backend requires root on Linux")
    ctl = load_backend()
    ctl.p.root_commands()
    lifecycle(ctl, args)


if __name__ == "__main__":
    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
        signal.signal(sig, interrupted)
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print("[STOP] " + (str(exc) if type(exc) is ValueError or type(exc).__name__ == "Refuse" else type(exc).__name__ + "; inspect backend manifest"))
        sys.exit(1)
