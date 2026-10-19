"""Explicit priority changes delegated to installed forpostctl, never collector."""
import hashlib
import os
from pathlib import Path
import re
import signal
import sys

from .core import DEFAULTS, channels, read_text
from .clients import Operation
from .ssh_session import resolve as ssh_connection

CTL = "/usr/local/sbin/forpostctl"


def lifecycle_plan(cfg, entity, action):
    p = maintenance_plan(cfg, entity, "off", allow_stopped=True)
    row = next(r for r in channels(cfg)[1] if r["id"] == entity)
    if action not in ("stop", "start") or row.get("stopped", False) is not (action == "start"):
        raise ValueError("Channel is already stopped or not stopped by Warden")
    if not re.fullmatch(r"awgfp[0-9]+", row["interface"]) or row["transport"] not in ("icmp", "faketcp", "wss"):
        raise ValueError("Stop/Start supports only registered awgfp ICMP/fakeTCP/WSS channels")
    if p["registry_sha256"] != hashlib.sha256(read_text(cfg["registry"]).encode()).hexdigest():
        raise ValueError("Registry changed; preview again")
    del p["state"]
    return dict(p, action=action)


def maintenance_plan(cfg, entity, state, allow_stopped=False):
    if cfg["registry"] != DEFAULTS["registry"] or state not in ("on", "off"):
        raise ValueError("Maintenance requires the standard registry and on/off state")
    raw = read_text(cfg["registry"])
    version, rows = channels(cfg)
    if version != "registry-v2" or raw != read_text(cfg["registry"]):
        raise ValueError("Registry unavailable or changed; preview again")
    row = next((r for r in rows if r["id"] == entity), None)
    if not row or row.get("retired"):
        raise ValueError("Choose a non-retired Forpost channel; permanent tunnels are not managed")
    if row.get("stopped") and not allow_stopped:
        raise ValueError("Channel is stopped; Start it before leaving Maintenance")
    if state == "on":
        if not row["enabled"]:
            raise ValueError("Channel is already excluded; no Maintenance operation started")
        if not any(r["enabled"] and r["id"] != entity for r in rows):
            raise ValueError("Refusing to exclude the last enabled channel")
    else:
        if not row.get("maintenance"):
            raise ValueError("Channel was not put into Maintenance by Warden")
        if not allow_stopped and any(r["enabled"] and r["id"] != entity and r["rank"] == row["rank"] for r in rows):
            raise ValueError("Priority is now occupied; resolve rank conflict before returning channel")
    return {"id": entity, "interface": row["interface"], "state": state,
            "registry_sha256": hashlib.sha256(raw.encode()).hexdigest()}


def plan(cfg, entity, rank):
    if cfg["registry"] != DEFAULTS["registry"]:
        raise ValueError("Administration requires the standard installed channel registry")
    if type(rank) is not int or not 1 <= rank <= 2147483647:
        raise ValueError("Priority must be an integer from 1 to 2147483647; lower is preferred")
    raw = read_text(cfg["registry"])
    version, rows = channels(cfg)
    if raw != read_text(cfg["registry"]):
        raise ValueError("Registry changed while reading; preview again")
    if version != "registry-v2":
        raise ValueError("Channel administration requires registry v2")
    row = next((r for r in rows if r["id"] == entity), None)
    if row is None or row.get("retired") or not row["enabled"]:
        raise ValueError("Choose an enabled, non-retired Forpost channel; permanent tunnels are not managed")
    if any(r["id"] != entity and r["enabled"] and r["rank"] == rank for r in rows):
        raise ValueError("Priority already used by another enabled channel; choose a free value")
    return {"id": entity, "interface": row["interface"], "old_rank": row["rank"], "rank": rank,
            "registry_sha256": hashlib.sha256(raw.encode()).hexdigest()}


def format_plan(p):
    if "action" in p:
        return [f"Channel: {p['id']} / {p['interface']} | {p['action'].capitalize()}",
                "Requires Maintenance and a freshly verified healthy current exit through another channel.",
                "Stop: stop this AWG and transport; persistent condition prevents automatic/boot restart.",
                "Start: restore this transport, AWG and probe routes; verify HTTPS; remain in Maintenance.",
                "Config files, keys, unit enablement, other channels and VLESS clients are preserved.",
                "Installed forpostctl owns SSH protection, shared lock, manifest and rollback."]
    if "state" in p:
        return [f"Channel: {p['id']} / {p['interface']} | Maintenance: {p['state']}",
                "On: exclude from selection only with a freshly verified healthy alternative.",
                "If active, move egress to the healthy alternative; existing connections may be interrupted.",
                "Off: verify this channel over HTTPS, re-enable; controller retains normal recovery hold.",
                "AWG/WSS/ICMP services, configs, probe rules and VLESS credentials are preserved.",
                "Installed forpostctl transaction backend owns shared lock, manifest and rollback."]
    return [f"Channel: {p['id']} / {p['interface']}", f"Priority: {p['old_rank']} -> {p['rank']} (lower is preferred)",
            "Backend: installed forpostctl set-priority; controller selects the egress.",
            "Selection may change after normal health/recovery checks; this is not an immediate switch.",
            "Backend briefly stops the selector, updates registry/units and restores its timer.",
            "Backend owns the policy lock, operation manifest and rollback."]


def backend(cfg, expected):
    current = (lifecycle_plan(cfg, expected["id"], expected["action"]) if "action" in expected else
               maintenance_plan(cfg, expected["id"], expected["state"]) if "state" in expected else
               plan(cfg, expected["id"], expected["rank"]))
    if current != expected:
        raise ValueError("Registry changed since preview; review a new plan")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Channel administration requires root on Linux")
    if not Path(CTL).is_file() or not os.access(CTL, os.X_OK):
        raise ValueError("Installed /usr/local/sbin/forpostctl unavailable; inspect its installation first")
    connection = ssh_connection()
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "SSH_CONNECTION": connection}
    if "action" in expected:
        return [sys.executable, "-B", str(Path(__file__).with_name("lifecycle_backend.py")),
                "--id", expected["id"], "--action", expected["action"], "--expected", expected["registry_sha256"]], env
    if "state" in expected:
        return [sys.executable, "-B", str(Path(__file__).with_name("maintenance_backend.py")),
                "--id", expected["id"], "--state", expected["state"], "--expected", expected["registry_sha256"]], env
    return [CTL, "set-priority", "--id", expected["id"], "--priority", str(expected["rank"]), "--apply"], env


def start(cfg, expected):
    return Operation(cfg, "priority", expected["id"], command=backend(cfg, expected))


def command(cfg, args):
    p = (lifecycle_plan(cfg, args.entity, args.command) if args.command in ("stop", "start") else
         maintenance_plan(cfg, args.entity, args.state) if args.command == "maintenance" else
         plan(cfg, args.entity, args.rank))
    print("\n".join(format_plan(p)), flush=True)
    if not args.run:
        print("PREVIEW ONLY: no backend commands run. Use --run to apply.")
        return 0
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {s: signal.signal(s, lambda *_: None) for s in signals}
    job = None
    try:
        job = start(cfg, p)
        job.wait()
        print("\n".join(job.result()))
        return 1 if job.returncode else 0
    finally:
        if job:
            job.wait()
        for s, handler in previous.items():
            signal.signal(s, handler)


class PriorityView:
    def __init__(self, cfg, entity, demo=False, maintenance=None, lifecycle=None):
        self.cfg, self.entity = cfg, entity
        self.mode, self.text, self.rows = "input", "", []
        self.operation, self.pending = None, None
        if demo:
            self.mode, self.rows = "result", ["DEMO: channel administration disabled."]
        elif maintenance is not None or lifecycle is not None:
            try:
                self.pending = lifecycle_plan(cfg, entity, lifecycle) if lifecycle else maintenance_plan(cfg, entity, maintenance)
                backend(cfg, self.pending)
                self.rows, self.mode = format_plan(self.pending), "confirm"
            except (OSError, ValueError) as exc:
                self.mode, self.rows = "result", [str(exc) if type(exc) is ValueError else "Backend unavailable; check paths/permissions"]

    def poll(self):
        if self.operation and self.operation.done():
            self.rows = self.operation.result()
            self.operation, self.mode = None, "result"
            return True
        return False

    def handle(self, event):
        if self.operation:
            return True
        if event in ("ESC", "q", "n"):
            self.mode = "closed"
            return True
        try:
            if self.mode == "input":
                if event == "BACKSPACE":
                    self.text = self.text[:-1]
                elif event == "ENTER":
                    self.pending = plan(self.cfg, self.entity, int(self.text or "0"))
                    backend(self.cfg, self.pending)  # preflight without execution
                    self.rows, self.mode = format_plan(self.pending), "confirm"
                elif event in "0123456789" and len(event) == 1 and len(self.text) < 10:
                    self.text += event
                return True
            if self.mode == "confirm" and event == "y":
                self.operation = start(self.cfg, self.pending)
                self.pending, self.mode = None, "running"
                return True
        except (OSError, ValueError) as exc:
            self.pending, self.mode = None, "result"
            self.rows = [str(exc) if type(exc) is ValueError else "Channel metadata unavailable; check paths/permissions"]
        return event not in ("UP", "DOWN", "PGUP", "PGDN")

    def render(self, width):
        from .tui import panel
        rows = (["New priority: " + self.text + "_", "Lower is preferred. Enter: preview | Esc: cancel"] if self.mode == "input" else
                ["Waiting for forpostctl to finish; operation cannot be cancelled halfway through."] if self.operation else
                self.rows + ["", "y: apply | n/Esc: cancel" if self.mode == "confirm" else "Esc: return to tunnels"])
        title = "CHANNEL MAINTENANCE" if self.pending and "state" in self.pending else "CHANNEL ADMIN"
        return panel(title + " / " + self.entity + " / " + self.mode.upper(), rows, width)
