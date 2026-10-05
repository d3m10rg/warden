"""Bounded, passive Linux observations. No network probes or modifying commands."""
import concurrent.futures
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from . import __version__
from .core import (SERVICES, active_route, channel_health, channels, clean,
                   controller_state, parse_peers, read_json, read_text,
                   service_state, vless_summary)


def command(argv):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=3, env=dict(os.environ, LC_ALL="C", SYSTEMD_PAGER="cat"))
        usable_units = argv[:2] == ["systemctl", "show"] and "Id=" in result.stdout
        if (result.returncode and not usable_units) or len(result.stdout) > 2_000_000:
            return None
        return result.stdout
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None


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


def journal_events(cursor=None, runner=command, since=None):
    """Read bounded switch-only journal entries. Persist cursor with DB transaction."""
    argv = ["journalctl", "--no-pager", "-o", "json", "-u", "ravelin-forpost-failover.service",
            "--grep=^Protected egress:", "-n", "500"]
    if cursor:
        argv += ["--after-cursor", cursor]
    else:
        argv += ["--since", "@" + str(int(since)) if since is not None else "48 hours ago"]
    output = runner(argv)
    cursor_recovered = False
    if output is None and cursor:
        # Journal rotation can invalidate a cursor; re-read a bounded time range.
        output = runner(argv[:-2] + ["--since", "48 hours ago"])
        cursor_recovered = True
    if output is None:
        return [], cursor, False
    import re
    events = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            match = re.fullmatch(r"Protected egress: ([\w-]+) -> ([\w-]+)", data.get("MESSAGE", ""))
            if match:
                events.append({"timestamp": int(data["__REALTIME_TIMESTAMP"]) / 1e6,
                               "kind": "controller_switch", "entity": "egress",
                               "detail": match.group(1) + " -> " + match.group(2),
                               "source_id": data["__CURSOR"]})
            cursor = data.get("__CURSOR", cursor)
        except (ValueError, TypeError, KeyError):
            continue
    return events, cursor, not cursor_recovered and len(output.splitlines()) < 500
