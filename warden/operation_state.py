"""Ephemeral progress observations; never a source of routing decisions."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import uuid

ROOT = Path("/run/warden/operations")
PROC = Path("/proc")
PHASES = {"Starting", "Waiting for server", "Stopping"}


def trusted(path):
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Symlink in operation observation path")
        if part.exists():
            st = part.stat()
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError("Unsafe operation observation path")


def identity(pid):
    # /proc stat field 22 disambiguates PID reuse; comm may contain spaces or ')'.
    fields = (PROC / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] in ("Z", "X", "x"):
        raise ValueError("Operation process has exited")
    return {"pid": pid, "start_ticks": int(fields[19]),
            "boot": (PROC / "sys/kernel/random/boot_id").read_text().strip()}


def load(path):
    trusted(path)
    with path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("Oversized operation observation")
    return json.loads(raw)


def read(entity, interface):
    if not re.fullmatch(r"awgfp[0-9]+", interface):
        return None
    try:
        value = load(ROOT / (interface + ".json"))
        if (value.get("version") != 1 or value.get("id") != entity or value.get("interface") != interface or
                value.get("phase") not in PHASES or type(value.get("pid")) is not int or value["pid"] <= 0 or
                value.get("action") not in ("start", "stop")):
            return None
        if (value["action"] == "stop") != (value["phase"] == "Stopping"):
            return None
        current = identity(value["pid"])
        if any(value.get(k) != current[k] for k in current):
            return None
        return {"action": value["action"], "phase": value["phase"]}
    except (OSError, ValueError, TypeError, AttributeError, IndexError, KeyError, UnicodeError):
        return None


@contextmanager
def observe(ctl, channel, action):
    """Best effort: progress IO must not prevent backend rollback or success."""
    path = ROOT / (channel["if"] + ".json")
    value = None
    try:
        trusted(path)
        value = dict(identity(os.getpid()), version=1, token=uuid.uuid4().hex,
                     id=channel["id"], interface=channel["if"], action=action)
    except (OSError, ValueError, IndexError, UnicodeError):
        ctl.say("NOTICE", "Operation progress unavailable; backend transaction still owns the operation")

    def update(phase):
        if phase not in PHASES:
            raise ValueError("Unknown operation phase")
        ctl.say("STATE", phase)
        if value is not None:
            value["phase"] = phase
            try:
                trusted(path)
                ctl.p.atomic(path, ctl.encode(value))
            except (OSError, ValueError, ctl.p.Refuse):
                ctl.say("NOTICE", "Cannot update operation progress; backend transaction continues")

    update("Starting" if action == "start" else "Stopping")
    try:
        yield update
    finally:
        if value is not None:
            try:
                if load(path).get("token") == value["token"]:
                    path.unlink()
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError, AttributeError):
                ctl.say("NOTICE", "Operation progress cleanup unavailable; exited processes are ignored")
