"""Explicit extension of installed forpostctl's transaction backend.

Never replaces its WSS-aware source, runtime, unit files or tunnel configuration.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import sys


def load_backend():
    wrapper = Path("/usr/local/sbin/forpostctl").resolve(strict=True)
    source = wrapper if wrapper.suffix == ".py" else wrapper.with_suffix(".py")
    for path in (source, *source.parents):
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError("Installed backend path must be root-owned and not writable by group/others")
    spec = importlib.util.spec_from_file_location("warden_installed_forpostctl", source)
    ctl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ctl)
    for name in ("registry", "change", "switch", "probe_candidate", "encode", "verify_vless"):
        if not callable(getattr(ctl, name, None)):
            raise ValueError("Installed forpostctl API unsupported; no changes made")
    if str(ctl.p.CHANNELS) != "/etc/ravelin-forpost/channels.json" or ctl.p.SOURCE != "10.78.254.2":
        raise ValueError("Unsupported backend registry/source; no changes made")
    return ctl


def guard(p):
    p.require(any(r.get("type") == "unreachable" and r.get("dst") == "default" for r in p.routes(10400)),
              "Protected unreachable default missing")
    rules = p.jrun("ip", "-j", "-4", "rule", "show")
    p.require(any(r.get("priority") == 99 and r.get("iif") == "lo" and
                  r.get("src") in (p.SOURCE, p.SOURCE+"/32") and str(r.get("table")) == "10400" for r in rules),
              "Protected local-source rule missing")


def maintain(ctl, args):
    p = ctl.p
    # Shared with the controller and every ordinary forpostctl mutation.
    with p.locked(wait_seconds=30):
        p.require(hashlib.sha256(p.CHANNELS.read_bytes()).hexdigest() == args.expected,
                  "Registry changed since preview; preview again")
        data = ctl.registry()
        channel = next((c for c in data["channels"] if c["id"] == args.id), None)
        p.require(channel is not None and not channel.get("retired"), "Channel absent or retired")
        entering = args.state == "on"
        p.require(channel["enabled"] if entering else
                  not channel["enabled"] and channel.get("maintenance") is True,
                  "Channel state changed or channel was not put into Maintenance by Warden")
        remaining = [c for c in data["channels"] if c["id"] != args.id and c["enabled"] and not c.get("retired")]
        p.require(not entering or remaining, "Refusing to exclude the last enabled channel")
        guard(p)
        channel["enabled"] = not entering
        channel["maintenance"] = entering
        p.validate_channels(data)  # Includes rank collisions on return.
        # change() records the baseline and stops selection; exceptions invoke
        # the installed backend's journaled rollback, including route restoration.
        with ctl.change("ravelin", args) as tx:
            if entering:
                active = p.active_route()
                p.require(active != "none", "No active exit; restore connectivity before Maintenance")
                healthy, _ = p.probe_paths()  # Current enabled runtime, before registry write.
                available = sorted((c for c in remaining if healthy.get(c["id"]) is True), key=lambda c: c["rank"])
                p.require(available, "No healthy alternative exit; Maintenance refused")
                if active == args.id:
                    ctl.switch(tx, available[0]["id"])
                else:
                    p.require(any(c["id"] == active for c in available), "Current alternative exit is unhealthy; Maintenance refused")
            else:
                ctl.probe_candidate(channel)  # Explicit diagnostics of the excluded channel.
            tx.file(p.CHANNELS, ctl.encode(data))
            p.load_channels()
            guard(p)
            if entering:
                p.require(p.active_route() != args.id, "Excluded channel still selected")
            ctl.verify_vless()
        ctl.say("OK", "Maintenance " + args.state + ": " + args.id + "; AWG and transport preserved")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--state", choices=("on", "off"), required=True)
    parser.add_argument("--expected", required=True)
    args = parser.parse_args()
    args.ssh_client, args.console = None, False
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Maintenance backend requires root on Linux")
    ctl = load_backend()
    ctl.p.root_commands()
    maintain(ctl, args)


if __name__ == "__main__":
    # Foreground Warden waits for this isolated worker; backend remains in
    # charge of transaction rollback for other interruptions/errors.
    def interrupted(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
        signal.signal(sig, interrupted)
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print("[STOP] " + (str(exc) if type(exc) is ValueError or type(exc).__name__ == "Refuse" else type(exc).__name__ + "; inspect backend manifest"))
        sys.exit(1)
