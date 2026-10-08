"""Bounded, passive Linux observations. No network probes or modifying commands."""
import concurrent.futures
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from . import __version__
from .core import (RETENTION, SERVICES, active_route, channel_health, channels, clean,
                   controller_state, number, parse_peers, read_json, read_text,
                   service_state, vless_summary)


def command(argv, diagnostics=None):
    def failure(reason):
        if diagnostics is not None:
            diagnostics["error"] = reason
        return None

    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=3, env=dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="cat"))
        # journalctl --grep uses exit 1 for no matches, as well as for errors.
        # Accept only a clean empty result; stderr, timeout or other output must
        # remain unavailable rather than hiding permission/cursor/read failures.
        empty_journal = (argv[0] == "journalctl" and
                         any(arg.startswith("--grep=") for arg in argv) and
                         result.returncode == 1 and not result.stderr.strip() and
                         result.stdout.strip() in ("", "-- No entries --"))
        if empty_journal:
            return ""
        usable_units = argv[:2] == ["systemctl", "show"] and "Id=" in result.stdout
        if result.returncode and not usable_units:
            reason = "cursor unavailable" if argv[0] == "journalctl" and "cursor" in result.stderr.lower() else "exit " + str(result.returncode)
            return failure(reason)
        if len(result.stdout) > 2_000_000:
            return failure("output size limit")
        if argv[0] == "journalctl" and result.stderr.strip():
            return failure("journalctl reported a warning/error")
        return result.stdout
    except subprocess.TimeoutExpired:
        return failure("timeout (3s)")
    except (OSError, UnicodeError) as exc:
        return failure(type(exc).__name__)


def json_rows(text):
    if text is None:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else None
    except ValueError:
        return None


def services(text):
    rows = []
    for block in (text or "").strip().split("\n\n"):
        row = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if row.get("Id") in SERVICES:
            rows.append({"id": row["Id"], "state": service_state(row),
                         "active": row.get("ActiveState"), "sub": row.get("SubState"),
                         "result": row.get("Result"), "exit_code": row.get("ExecMainStatus")})
    by_id = {r["id"]: r for r in rows}
    return [by_id.get(name, {"id": name, "state": "Unknown"}) for name in SERVICES]


def collect(cfg, runner=command, clock=time.time, monotonic=time.monotonic):
    started = monotonic()
    now = clock()
    errors = []
    try:
        boot = read_text("/proc/sys/kernel/random/boot_id").strip()
    except OSError:
        boot = "unknown"
        errors.append("Boot ID unavailable; Linux is required")
    try:
        version, paths = channels(cfg)
    except (OSError, ValueError, SyntaxError, TypeError, KeyError, AttributeError):
        version, paths = "unknown", []
        errors.append("Channel metadata unavailable/unsupported; no controller code was executed")
    try:
        health = read_json(cfg["health"])
        if not isinstance(health.get("healthy"), dict) or not isinstance(health.get("paths"), dict):
            raise ValueError("invalid health")
    except (OSError, ValueError, TypeError):
        health = {}
        errors.append("Controller state unavailable/invalid")
    tasks = {
        "links": ["ip", "-j", "-s", "link", "show"],
        "routes": ["ip", "-j", "-4", "route", "show", "table", "10400"],
        "rules": ["ip", "-j", "-4", "rule", "show"],
        "units": ["systemctl", "show", "--no-pager", *SERVICES, "--property=Id,LoadState,Type,ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestampMonotonic"],
        "listeners": ["ss", "-H", "-lnt"],
    }
    for tool in ("awg", "wg"):
        tasks[tool + ":interfaces"] = [tool, "show", "interfaces"]
        for field in ("endpoints", "latest-handshakes", "transfer", "allowed-ips"):
            tasks[tool + ":" + field] = [tool, "show", "all", field]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {name: pool.submit(runner, argv) for name, argv in tasks.items()}
        outputs = {name: future.result() for name, future in futures.items()}
    links = json_rows(outputs["links"])
    routes = json_rows(outputs["routes"])
    rules = json_rows(outputs["rules"])
    for name, value in (("links", links), ("routes", routes), ("rules", rules)):
        if value is None:
            errors.append(name + " unavailable")
    if outputs["units"] is None:
        errors.append("systemd observations unavailable")
    by_if = {r["ifname"]: r for r in (links or []) if "ifname" in r}
    interface_tools, all_peers = {}, {}
    for tool in ("awg", "wg"):
        # Prefer AWG if both tools expose the same interface.
        interfaces = (outputs[tool + ":interfaces"] or "").split()
        peer_rows = parse_peers({f: outputs[tool + ":" + f] for f in ("endpoints", "latest-handshakes", "transfer", "allowed-ips")})
        for interface in interfaces:
            if interface in interface_tools:
                continue
            interface_tools[interface] = tool
            all_peers[interface] = [p for p in peer_rows if p["interface"] == interface]
    if outputs["awg:interfaces"] is None and outputs["wg:interfaces"] is None:
        errors.append("AWG/WG observations unavailable (root access/tools may be required)")
    controller = controller_state(health, boot, started)
    active = active_route(routes, paths) if routes is not None else "unknown"
    controller.update({"version": version, "active": active})
    if controller["fresh"] and active != controller["reported_active"]:
        errors.append("Controller selection differs from kernel route (or changed during observation)")
    guard = any(r.get("dst") == "default" and r.get("type") == "unreachable" for r in routes or [])
    source_rule = any(r.get("priority") == 99 and r.get("iif") == "lo" and
                      r.get("src") in ("10.78.254.2", "10.78.254.2/32") and str(r.get("table")) == "10400" for r in rules or [])
    controller["unreachable_guard"] = guard if routes is not None else None
    controller["local_source_rule"] = source_rule if rules is not None else None
    if routes is not None and not guard:
        errors.append("Protected unreachable default missing")
    if rules is not None and not source_rule:
        errors.append("Expected local-only source rule 99 missing")
    objects = []
    path_interfaces = {p["interface"] for p in paths}
    inventory = paths + [{"id": interface, "name": cfg["names"].get(interface, interface),
                          "interface": interface, "note": cfg["notes"].get(interface, "")}
                         for interface in sorted(interface_tools) if interface not in path_interfaces]
    for item in inventory:
        interface = item["interface"]
        link = by_if.get(interface)
        peers = sorted(all_peers.get(interface, []), key=lambda p: p["peer_id"])
        rows = []
        for peer in peers:
            row = dict(peer)
            hs = row["handshake"]
            row["handshake_age_seconds"] = now - hs if hs and 0 <= hs <= now else None
            row["name"] = cfg["peer_names"].get(peer["peer_id"], ",".join(peer["allowed_ips"]) or peer["peer_id"])
            row["health"] = "Recent handshake" if row["handshake_age_seconds"] is not None and row["handshake_age_seconds"] <= 180 else "Unknown"
            # Endpoint/AllowedIPs changes split counters even if ifindex is reused.
            row["generation"] = hashlib.sha256(json.dumps([link.get("ifindex") if link else None, peer["peer_id"], peer["endpoint"], peer["allowed_ips"]], sort_keys=True).encode()).hexdigest()[:16]
            rows.append(row)
        stats = ((link or {}).get("stats64") or (link or {}).get("stats") or {})
        is_channel = interface in path_interfaces
        if is_channel:
            try:
                status, reason = channel_health(item["id"], link is not None, controller["fresh"], health, item["enabled"])
            except (AttributeError, TypeError):
                status, reason = "Unknown", "Invalid channel health record"
            if links is None:
                status, reason = "Unknown", "Interface observation unavailable"
            role = "Active" if active == item["id"] else "Standby" if status == "Healthy" and item["enabled"] else "None"
        else:
            recent = sum(r["health"] == "Recent handshake" for r in rows)
            status = "Observed" if recent else "Unknown"
            reason = f"{recent}/{len(rows)} peers with recent handshake; connectivity not tested"
            role = "N/A"
        row = dict(item, kind="Failover member" if is_channel else "Permanent / unmanaged",
                   role=role, health=status, reason=reason,
                   tool=interface_tools.get(interface), peers=rows,
                   rx=stats.get("rx", {}).get("bytes"), tx=stats.get("tx", {}).get("bytes"),
                   rx_errors=stats.get("rx", {}).get("errors"), tx_errors=stats.get("tx", {}).get("errors"),
                   generation=hashlib.sha256(json.dumps([(link or {}).get("ifindex"), [(p["peer_id"], p["generation"]) for p in rows]], sort_keys=True).encode()).hexdigest()[:16],
                   public_reachability="Not tested", private_reachability="Not tested")
        objects.append(row)
    try:
        vless = vless_summary(cfg["vless"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        vless = {"error": "VLESS configuration unavailable/unsupported", "client_session": "Not tested"}
    listeners = set()
    for line in (outputs["listeners"] or "").splitlines():
        fields = line.split()
        if len(fields) >= 4:
            listeners.add(fields[3])
    for row in vless.get("listeners", []):
        row["listening"] = (row["address"] + ":" + str(row["port"])) in listeners if outputs["listeners"] is not None else None
    vless["protected_source_configured"] = vless.get("source_addresses") == ["10.78.254.2"] if "source_addresses" in vless else None
    return {"schema_version": 1, "warden_version": __version__, "timestamp": now, "monotonic": started,
            "boot": boot, "duration_seconds": max(0, monotonic() - started),
            "controller": controller, "tunnels": objects, "services": services(outputs["units"]),
            "vless": vless, "warnings": errors}


def journal_events(cursor=None, runner=command, since=None, diagnostics=None, clock=time.time):
    """Read the FIRST 500 unit entries forward; retain only allowlisted switches.

    Do not use --grep: -n without '+' implicitly reverses grep results, and a
    rare-message filter does not bound the number of unit entries scanned.
    """
    info = diagnostics if diagnostics is not None else {}
    info.update(reader_version=2, checked_at=clock(), status="Error", error=None,
                records=0, cursor_recovered=False)
    lower = max(info["checked_at"] - RETENTION, min(since, info["checked_at"]-2)) if number(since) else info["checked_at"] - RETENTION
    if number(since) and not info["checked_at"]-RETENTION <= since <= info["checked_at"]:
        cursor = None
    argv = ["journalctl", "--no-pager", "-o", "json", "-u", "ravelin-forpost-failover.service",
            "--output-fields=MESSAGE", "-n", "+500"]
    if cursor:
        argv += ["--after-cursor", cursor]
    else:
        argv += ["--since", "@" + str(int(lower))]

    def read(args):
        started = time.monotonic()
        result = runner(args, diagnostics=info) if runner is command else runner(args)
        info["duration_seconds"] = round(time.monotonic() - started, 3)
        return result

    output = read(argv)
    cursor_recovered = False
    if output is None and cursor and info.get("error") == "cursor unavailable":
        # A timeout/permission failure must not trigger a second expensive scan.
        output = read(argv[:-2] + ["--since", "@" + str(int(lower))])
        cursor_recovered = True
        if output is not None:
            cursor = ""  # Clear a rotated cursor even when recovery is empty.
    if output is None:
        info["error"] = info.get("error") or "read unavailable"
        return [], cursor, False
    import re
    events = []
    info.update(error=None, cursor_recovered=cursor_recovered)
    if output.strip() == "-- No entries --":
        output = ""
    last_timestamp = None
    for line in output.splitlines():
        try:
            data = json.loads(line)
            stamp = int(data["__REALTIME_TIMESTAMP"]) / 1e6
            next_cursor = data["__CURSOR"]
            if not isinstance(next_cursor, str) or not next_cursor or not number(stamp):
                raise ValueError()
            message = data.get("MESSAGE", "")
            match = re.fullmatch(r"Protected egress: ([\w-]+) -> ([\w-]+)", message) if isinstance(message, str) else None
            if match:
                events.append({"timestamp": stamp,
                               "kind": "controller_switch", "entity": "egress",
                               "detail": match.group(1) + " -> " + match.group(2),
                               "source_id": data["__CURSOR"]})
            cursor = next_cursor
            last_timestamp = stamp
            info["records"] += 1
        except (ValueError, TypeError, KeyError):
            # Do not advance beyond an unreadable entry or call it complete.
            info["error"] = "invalid journal entry"
            return events, cursor, False
    complete = info["records"] < 500
    info["status"] = "Ready" if complete else "Catching up"
    # On recovery, retain a visible history completeness warning for this read.
    info["watermark"] = info["checked_at"]-2 if complete else last_timestamp-2
    return events, cursor, complete


class JournalPoller:
    """Back off failed journal reads without delaying normal observations."""
    def __init__(self):
        self.retry_at = 0
        self.failures = 0
        self.info = {}

    def poll(self, cursor, since, reader=journal_events, monotonic=time.monotonic):
        now = monotonic()
        if now < self.retry_at:
            self.info["retry_in_seconds"] = max(1, round(self.retry_at-now))
            return [], cursor, None
        self.info = {}
        events, cursor, complete = reader(cursor, since=since, diagnostics=self.info)
        if self.info.get("error"):
            self.failures = min(5, self.failures+1)
            delay = min(600, 60 * 2**(self.failures-1))
            self.retry_at = monotonic() + delay
            self.info["retry_in_seconds"] = delay
        else:
            self.failures = 0
            self.retry_at = 0
        return events, cursor, self.info.get("watermark")

    def warning(self):
        if self.info.get("error"):
            return "Switch journal: " + self.info["error"] + "; retry in " + str(self.info.get("retry_in_seconds", 0)) + "s"
        if self.info.get("status") == "Catching up":
            return "Switch journal catching up (500 unit records per cycle); history not current yet"
        if self.info.get("cursor_recovered"):
            return "Switch journal cursor recovered by time; completeness across rotation is not guaranteed"
        return None
