"""Explicit, bounded diagnostics. Never writes routes or controller state."""
import contextlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time

from .core import NAME, STALE_SECONDS, controller_literals, number
from .linux import command, json_rows


def ipv4(value):
    try:
        if not isinstance(value, str):
            raise ValueError()
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback or int(address) == 0xffffffff:
            raise ValueError()
        return str(address)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        raise ValueError("Diagnostics require a unicast IPv4 literal") from None


def validate_config(value):
    if not isinstance(value, dict):
        raise ValueError("diagnostics must map tunnel IDs to targets")
    for key, row in value.items():
        if not isinstance(key, str) or not NAME.fullmatch(key) or not isinstance(row, dict):
            raise ValueError("Invalid diagnostics entry")
        if set(row) - {"internal", "external", "speed_host", "speed_port"}:
            raise ValueError("Unknown diagnostics target field")
        for name in ("internal", "external", "speed_host"):
            if name in row:
                ipv4(row[name])
        if "speed_port" in row and (type(row["speed_port"]) is not int or not 1 <= row["speed_port"] <= 65535):
            raise ValueError("speed_port must be 1..65535")


def route_get(target, source=None, interface=None, mark=None, runner=command):
    argv = ["ip", "-j", "-4", "route", "get", ipv4(target)]
    if source:
        argv += ["from", ipv4(source)]
    if mark is not None:
        argv += ["mark", str(mark)]
    if interface:
        argv += ["oif", interface]
    rows = json_rows(runner(argv))
    if not rows or len(rows) != 1 or rows[0].get("type", "unicast") != "unicast":
        raise ValueError("No unambiguous unicast route; no probe sent")
    return rows[0]


def plan(data, cfg, entity, kind, seconds=5, mbps=5, reverse=False, runner=command):
    """Use fresh host data; plans are rebuilt immediately before execution."""
    if not 0 <= time.time() - data["timestamp"] <= STALE_SECONDS:
        raise ValueError("Fresh live observation required for diagnostics")
    row = next((r for r in data["tunnels"] if r["id"] == entity), None)
    if row is None:
        raise ValueError("Unknown tunnel; use warden list")
    dev = row["interface"]
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", dev):
        raise ValueError("Unsupported interface name")
    extra = cfg.get("diagnostics", {}).get(entity, {})
    result = {"entity": entity, "kind": kind, "interface": dev, "source": row.get("local"),
              "mark": None, "table": None, "timestamp": time.time()}
    if kind == "https":
        if row.get("kind") != "Failover member":
            raise ValueError("HTTPS egress check requires controller channel metadata")
        constants = controller_literals(cfg["engine"], ("SOURCE", "TARGETS"))
        targets = constants.get("TARGETS")
        if not isinstance(targets, (tuple, list)) or not targets:
            raise ValueError("Controller HTTPS targets unavailable")
        target = targets[0]
        if not isinstance(target, (tuple, list)) or len(target) != 3:
            raise ValueError("Unsupported controller HTTPS target")
        host, path = target[1:]
        if not isinstance(host, str) or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", host):
            raise ValueError("Invalid HTTPS hostname")
        if not isinstance(path, str) or not re.fullmatch(r"/[a-zA-Z0-9/_.?=&%-]{0,255}", path):
            raise ValueError("Unsupported HTTPS path")
        for key in ("mark", "table"):
            if type(row.get(key)) is not int or not 1 <= row[key] <= 0x7fffffff:
                raise ValueError("Missing controller probe mark/table")
        result.update(target=ipv4(target[0]), host=host, path=path,
                      source=ipv4(constants.get("SOURCE")), mark=row["mark"], table=row["table"])
    elif kind in ("internal", "external", "speed"):
        default = row.get("peer" if kind == "internal" else "public") if kind != "speed" else None
        field = "speed_host" if kind == "speed" else kind
        target = extra.get(field, default)
        if target is None:
            raise ValueError(f"Configure diagnostics.{entity}.{field} before this test")
        result["target"] = ipv4(target)
        if kind == "external":
            route = route_get(result["target"], runner=runner)
            dev = route.get("dev")
            tunnel_devs = {r["interface"] for r in data["tunnels"]}
            if not dev or dev in tunnel_devs or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", dev):
                raise ValueError("External address is not routed through an observed non-tunnel interface")
            result.update(interface=dev, source=route.get("prefsrc") or route.get("src"))
        if kind == "speed":
            if type(seconds) is not int or not 1 <= seconds <= 10 or type(mbps) is not int or not 1 <= mbps <= 10:
                raise ValueError("Speed limits: 1..10 seconds and 1..10 Mbit/s")
            result.update(seconds=seconds, mbps=mbps, reverse=bool(reverse), port=extra.get("speed_port", 5201))
    else:
        raise ValueError("Unknown diagnostic kind")
    route = route_get(result["target"], result["source"], result["interface"], result["mark"], runner)
    if route.get("dev") != result["interface"]:
        raise ValueError("Route does not use the selected interface; no probe sent")
    if result["table"] is not None:
        routes = json_rows(runner(["ip", "-j", "-4", "route", "show", "table", str(result["table"])]))
        if str(route.get("table")) != str(result["table"]) or not any(
                r.get("dst") == "default" and r.get("type") == "unreachable" for r in routes or []):
            raise ValueError("Probe table or unreachable guard mismatch; no probe sent")
    result["source"] = ipv4(result["source"] or route.get("prefsrc") or route.get("src"))
    # Check the exact tuple used by the probe, including an inferred source.
    exact = route_get(result["target"], result["source"], result["interface"], result["mark"], runner)
    if exact.get("dev") != result["interface"] or (result["table"] is not None and str(exact.get("table")) != str(result["table"])):
        raise ValueError("Source-bound route mismatch; no probe sent")
    result["tool"] = "python TLS" if kind == "https" else "iperf3" if kind == "speed" else "ping"
    result["limit"] = (f"{seconds}s / {mbps} Mbit/s / 1 TCP stream" if kind == "speed" else
                       "5s / one TLS connection / max 1024 response bytes" if kind == "https" else "3 packets / 5s")
    return result


@contextlib.contextmanager
def diagnostic_lock():
    if sys.platform != "linux":
        raise ValueError("Active diagnostics require Linux")
    import fcntl
    fd = os.open("/run/warden-diagnostics.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another Warden diagnostic is running") from None
        yield
    finally:
        os.close(fd)


def subprocess_probe(argv, timeout):
    # Clean environment prevents DNS/proxy/config surprises from shell settings.
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                   "IPUTILS_PING_PTR_LOOKUP": "0"}) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except BaseException:
                proc.kill()
                proc.communicate()
                raise
            if len(stdout) > 100000 or len(stderr) > 10000:
                raise ValueError("Unexpected diagnostic output size")
            return proc.returncode, stdout, stderr
    except FileNotFoundError:
        raise ValueError("Required diagnostic tool is not installed") from None


def https_probe(p):
    deadline = time.monotonic() + 5
    context = ssl.create_default_context()

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError()
        return budget

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (p["interface"] + "\0").encode())
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, p["mark"])
        raw.bind((p["source"], 0))
        raw.settimeout(remaining())
        raw.connect((p["target"], 443))
        with context.wrap_socket(raw, server_hostname=p["host"], do_handshake_on_connect=False) as tls:
            tls.settimeout(remaining())
            tls.do_handshake()
            tls.settimeout(remaining())
            tls.sendall(("GET " + p["path"] + " HTTP/1.1\r\nHost: " + p["host"] +
                         "\r\nConnection: close\r\n\r\n").encode("ascii"))
            response = b""
            while b"\r\n" not in response and len(response) < 1024:
                tls.settimeout(remaining())
                chunk = tls.recv(min(128, 1024-len(response)))
                if not chunk:
                    break
                response += chunk
    match = re.match(rb"HTTP/1\.[01] ([0-9]{3})(?: |\r)", response)
    code = int(match[1]) if match else None
    return {"status": "Passed" if code == 200 else "Failed", "http_status": code,
            "tls_verified": True, "detail": "One target; not a VLESS client session test"}


def execute(p):
    started = time.monotonic()
    try:
        if p["kind"] == "https":
            result = https_probe(p)
        elif p["kind"] == "speed":
            argv = ["iperf3", "-4", "-c", p["target"], "-p", str(p["port"]), "-B", p["source"],
                    "--bind-dev", p["interface"], "-t", str(p["seconds"]), "-b", str(p["mbps"] * 1000000),
                    "-P", "1", "-J", "--connect-timeout", "2000"]
            if p["reverse"]:
                argv.append("-R")
            code, stdout, stderr = subprocess_probe(argv, p["seconds"] + 5)
            raw = json.loads(stdout) if not code else {}
            received = raw.get("end", {}).get("sum_received", {}).get("bits_per_second")
            sent = raw.get("end", {}).get("sum_sent", {}).get("bits_per_second")
            ok = not code and not stderr and not raw.get("error") and number(received) and number(sent)
            result = {"status": "Passed" if ok else "Error", "received_bps": received if ok else None,
                      "sent_bps": sent if ok else None, "direction": "download" if p["reverse"] else "upload",
                      "detail": "Capped throughput, not maximum capacity" if ok else "iperf3 failed; check server and tool support"}
        else:
            code, stdout, stderr = subprocess_probe(["ping", "-4", "-n", "-q", "-c", "3", "-i", "1", "-W", "1",
                "-w", "5", "-I", p["interface"], "-I", p["source"], p["target"]], 7)
            counts = re.search(r"(\d+) packets transmitted, (\d+) received", stdout)
            rtt = re.search(r"= [\d.]+/([\d.]+)/", stdout)
            received = int(counts[2]) if counts else None
            sent = int(counts[1]) if counts else None
            status = "Reachable" if received and code in (0, 1) else "No reply" if received == 0 and code == 1 else "Error"
            if stderr.strip():
                status = "Error"
            result = {"status": status, "sent": sent, "received": received,
                      "loss_percent": round(100*(sent-received)/sent, 1) if sent else None,
                      "rtt_ms": float(rtt[1]) if rtt else None,
                      "detail": "No ICMP reply does not prove the host is down"}
    except ssl.SSLCertVerificationError:
        result = {"status": "Failed", "detail": "TLS certificate verification failed"}
    except (TimeoutError, subprocess.TimeoutExpired):
        result = {"status": "Timeout", "detail": "Diagnostic time budget exceeded"}
    except (OSError, ValueError, TypeError, AttributeError):
        result = {"status": "Error", "detail": "Probe failed; check connectivity, permissions and required tools"}
    return dict(result, plan=p, timestamp=time.time(), duration_seconds=round(time.monotonic()-started, 3))


def doctor(data):
    """Allowlist only: no addresses, peers, config text, journal, usernames or paths."""
    ctrl = data["controller"]
    checks = [{"check": "controller_observations", "ok": ctrl.get("fresh") is True},
              {"check": "unreachable_guard", "ok": ctrl.get("unreachable_guard") is True},
              {"check": "local_source_rule", "ok": ctrl.get("local_source_rule") is True}]
    return {"schema_version": 1, "timestamp": data["timestamp"], "checks": checks,
            "tunnel_counts": {state: sum(r["health"] == state for r in data["tunnels"])
                              for state in ("Healthy", "Degraded", "Down", "Observed", "Unknown")},
            "services": [{"id": r["id"], "state": r["state"]} for r in data["services"]],
            "tools": {tool: shutil.which(tool) is not None for tool in ("ip", "ping", "iperf3")},
            "observation_warnings": len(data["warnings"]), "client_session": "Not tested",
            "note": "Passive report; diagnostics send traffic only with --run or TUI confirmation"}


def format_result(result):
    p = result.get("plan", result)
    lines = [f"{p['entity']} / {p['kind']} -> {p['target']}",
             f"Interface: {p['interface']} | source: {p['source']} | {p['limit']}"]
    if p.get("table") is not None:
        lines.append(f"Probe table: {p['table']} | mark: {p['mark']}")
    if "status" not in result:
        return lines + ["PREVIEW ONLY: no packets sent. Use --run to execute."]
    lines += ["Result: " + result["status"]]
    for key in ("rtt_ms", "loss_percent", "http_status", "sent_bps", "received_bps", "direction", "detail"):
        if key in result:
            lines.append(f"{key}: {result[key]}")
    return lines
