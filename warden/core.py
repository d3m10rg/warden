"""Pure parsing and status rules. Never imports or executes the routing controller."""
import ast
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path, PurePosixPath

STALE_SECONDS = 30
RETENTION = 48 * 3600
NAME = re.compile(r"^[a-zA-Z0-9_.:-]{1,80}$")
DEFAULTS = {
    "engine": "/usr/local/libexec/ravelin-policy-routing.py",
    "registry": "/etc/ravelin-forpost/channels.json",
    "health": "/run/ravelin-forpost/policy-health.json",
    "vless": "/etc/sing-box/vless-ws.json",
    "database": "/var/lib/warden/warden.sqlite3",
    "names": {},
    "notes": {},
    "peer_names": {},
}
SERVICES = (
    "ravelin-forpost-failover.service", "ravelin-forpost-failover.timer",
    "ravelin-forpost-routing.service", "sing-box-vless-ws.service", "nginx.service",
    "ravelin-vless-traffic-exporter.service", "ravelin-vless-traffic-accounting.service",
    "ravelin-channel-alerts.timer", "strongswan-starter.service", "wg-quick@wg0.service",
)


def clean(value, limit=160):
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def read_text(path, limit=2_000_000):
    with Path(path).open("r", encoding="utf-8") as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise ValueError("file too large")
    return text


def read_json(path):
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def config(path):
    value = dict(DEFAULTS)
    if Path(path).exists():
        extra = read_json(path)
        if set(extra) - set(value):
            raise ValueError("unknown configuration fields")
        value.update(extra)
    for key in ("engine", "registry", "health", "vless", "database"):
        if not isinstance(value[key], str) or not (Path(value[key]).is_absolute() or PurePosixPath(value[key]).is_absolute()):
            raise ValueError(key + " must be an absolute path")
    for key in ("names", "notes", "peer_names"):
        if not isinstance(value[key], dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value[key].items()):
            raise ValueError(key + " must map names to strings")
        value[key] = {k: clean(v) for k, v in value[key].items()}
    return value


def channels(cfg):
    """Return allowlisted metadata from registry v2, or literal v1 PATHS."""
    if Path(cfg["registry"]).exists():
        data = read_json(cfg["registry"])
        if data.get("version") != 2 or not isinstance(data.get("channels"), list):
            raise ValueError("unsupported channel registry")
        raw = data["channels"]
        version = "registry-v2"
    else:
        tree = ast.parse(read_text(cfg["engine"]))
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in ("PATHS", "SOURCE", "VERSION"):
                        constants[target.id] = ast.literal_eval(node.value)
        if constants.get("VERSION") != 1 or not isinstance(constants.get("PATHS"), dict):
            raise ValueError("unsupported controller; discovery only")
        raw = [dict(path, id=key) for key, path in constants["PATHS"].items()]
        version = "controller-v1"
    result = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("invalid channel")
        key, interface = item.get("id"), item.get("if")
        if not isinstance(key, str) or not NAME.fullmatch(key) or not isinstance(interface, str) or not NAME.fullmatch(interface):
            raise ValueError("invalid channel identifier")
        for field in ("peer", "local", "public"):
            ipaddress.ip_address(item[field])
        enabled = item.get("enabled", True)
        if type(enabled) is not bool or type(item.get("retired", False)) is not bool:
            raise ValueError("invalid channel flags")
        rank = item.get("rank")
        if rank is not None and (type(rank) is not int or rank <= 0):
            raise ValueError("invalid rank")
        result.append({"id": key, "interface": interface,
                       "name": cfg["names"].get(key, clean(item.get("name", key))),
                       "peer": item["peer"], "local": item["local"], "public": item["public"],
                       "rank": rank, "enabled": enabled and not item.get("retired", False),
                       "note": cfg["notes"].get(key, "")})
    if len({c["id"] for c in result}) != len(result) or len({c["interface"] for c in result}) != len(result):
        raise ValueError("duplicate channels")
    return version, result


def peer_id(key):
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def parse_peers(texts):
    """Only selected show fields are used; private/preshared keys are never requested."""
    peers = {}
    for field, text in texts.items():
        if text is None:
            continue
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3 or not NAME.fullmatch(parts[0]):
                continue
            interface, key = parts[:2]
            pid = peer_id(key)
            row = peers.setdefault((interface, pid), {"peer_id": pid, "interface": interface,
                "endpoint": None, "allowed_ips": [], "handshake": None, "rx": None, "tx": None})
            try:
                if field == "latest-handshakes":
                    row["handshake"] = max(0, int(parts[2]))
                elif field == "transfer" and len(parts) == 4:
                    row["rx"], row["tx"] = max(0, int(parts[2])), max(0, int(parts[3]))
                elif field == "allowed-ips":
                    row["allowed_ips"] = [str(ipaddress.ip_network(v, strict=False)) for v in " ".join(parts[2:]).replace(",", " ").split() if v != "(none)"]
                elif field == "endpoints" and parts[2] != "(none)":
                    row["endpoint"] = clean(parts[2])
            except ValueError:
                continue
    return list(peers.values())


def controller_state(data, boot, mono):
    checked = data.get("checked_at")
    age = mono - checked if number(checked) else None
    fresh = data.get("boot") == boot and age is not None and 0 <= age <= STALE_SECONDS
    return {"fresh": fresh, "age_seconds": age if age is not None and age >= 0 else None,
            "reported_active": clean(data.get("active", "unknown"))}


def active_route(routes, paths):
    defaults = [r for r in routes if r.get("dst") == "default" and r.get("type", "unicast") == "unicast"]
    if not defaults:
        return "none"
    if len(defaults) != 1:
        return "unknown"
    row = defaults[0]
    matches = [p["id"] for p in paths if row.get("dev") == p["interface"] and row.get("gateway") == p["peer"]]
    return matches[0] if len(matches) == 1 else "unknown"


def channel_health(key, interface_present, fresh, data, enabled=True):
    if not interface_present:
        return "Down", "Interface absent"
    if not enabled:
        return "Unknown", "Excluded from controller probes"
    if not fresh:
        return "Unknown", "Controller observations unavailable or stale"
    health = data.get("healthy", {}).get(key)
    if health is True:
        return "Healthy", "Controller HTTPS probe passed"
    if health is False:
        failures = data.get("paths", {}).get(key, {}).get("failures")
        if type(failures) is not int:
            return "Unknown", "Invalid failure counter"
        return ("Down" if failures >= 3 else "Degraded"), "Controller HTTPS probe failed"
    return "Unknown", "No controller result"


def service_state(row):
    if row.get("LoadState") == "not-found":
        return "Absent"
    if row.get("ActiveState") == "failed" or row.get("Result") not in (None, "", "success"):
        return "Failed"
    if row.get("ActiveState") == "active":
        return "Running" if row.get("SubState") == "running" else "Ready"
    if row.get("ActiveState") == "activating":
        return "Checking"
    if row.get("Type") == "oneshot" and row.get("Result") == "success" and row.get("ExecMainStatus") == "0" and row.get("ExecMainExitTimestampMonotonic", "0") != "0":
        return "Idle (last run OK)"
    return "Inactive" if row.get("ActiveState") == "inactive" else "Unknown"


def vless_summary(path):
    data = read_json(path)
    inputs = [i for i in data.get("inbounds", []) if i.get("type") == "vless"]
    outputs = [o for o in data.get("outbounds", []) if o.get("type") == "direct"]
    return {"users": sum(len(i.get("users", [])) for i in inputs),
            "listeners": [{"address": clean(i.get("listen", "")), "port": i.get("listen_port"),
                           "transport": clean((i.get("transport") or {}).get("type", ""))} for i in inputs],
            "direct_outbounds": len(outputs),
            "source_addresses": sorted({clean(o.get("inet4_bind_address", "unspecified")) for o in outputs}),
            "marked_outbounds": sum("routing_mark" in o for o in outputs),
            "client_session": "Not tested"}
