"""Explicit client administration; never called by the collector."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

from .core import DEFAULTS, read_json

HELPER = Path(__file__).resolve().parent.parent / "helpers" / "manage-ravelin-vless-ws-users.sh"
USER_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
ACTIONS = ("show", "add", "rotate", "remove")


def names(cfg):
    """Return names only. No UUIDs, subscription tokens, writes or subprocesses."""
    data = read_json(cfg["vless"])
    inbounds = data.get("inbounds")
    if not isinstance(inbounds, list):
        raise ValueError("Invalid VLESS inbound")
    inbound = [i for i in inbounds if isinstance(i, dict) and
               i.get("tag") == "vless-ws" and i.get("type") == "vless"]
    if len(inbound) != 1:
        raise ValueError("Expected exactly one vless-ws inbound")
    users = inbound[0].get("users")
    if not isinstance(users, list) or not users:
        raise ValueError("VLESS user list is empty or invalid")
    result = []
    for user in users:
        name = user.get("name") if isinstance(user, dict) else None
        if not isinstance(name, str) or not USER_NAME.fullmatch(name) or name == "all":
            raise ValueError("VLESS user list contains an invalid name")
        if not isinstance(user.get("uuid"), str) or not user["uuid"]:
            raise ValueError("VLESS user list contains invalid credentials")
        result.append(name)
    if len(set(result)) != len(result):
        raise ValueError("VLESS user list contains duplicate names")
    return result


def preview(cfg, action, name):
    if action not in ACTIONS:
        raise ValueError("Unknown client action")
    if not isinstance(name, str) or not USER_NAME.fullmatch(name) or (name == "all" and action != "show"):
        raise ValueError("Use a client name: 1-64 letters, digits, dot, underscore or dash; all is for show only")
    # The existing backend owns this exact inbound/service. Never preview a
    # different file and then silently operate on the production default.
    if cfg["vless"] != DEFAULTS["vless"]:
        raise ValueError("Client management requires the standard /etc/sing-box/vless-ws.json path")
    current = names(cfg)
    if action == "add" and name in current:
        raise ValueError("Client already exists")
    if action != "add" and name != "all" and name not in current:
        raise ValueError("Unknown client")
    if action == "remove" and len(current) == 1:
        raise ValueError("Refusing to remove the last client")
    lines = [f"Client operation: {action} {name}"]
    if action == "show":
        lines += ["Synchronize subscriptions, check and reload nginx; display private client links.",
                  "Existing UUIDs and subscription URLs are retained."]
    else:
        lines += ["Validate and back up sing-box config; synchronize installed traffic accounting.",
                  "Restart sing-box-vless-ws.service: client connections may be interrupted.",
                  "Synchronize subscriptions, check and reload nginx."]
        if action == "rotate":
            lines += ["Revoke old VLESS URI. Keep subscription URL; refresh it in the client to get the new URI."]
        elif action == "remove":
            lines += ["Revoke this client's access and remove its subscription files."]
        else:
            lines += ["Create client credentials and display VLESS, generic and Happ subscription links."]
    return lines


def execute(cfg, action, name):
    preview(cfg, action, name)  # Recheck before handing ownership to backend lock.
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Client operations require root on Linux")
    if not HELPER.is_file() or not Path(cfg["clients_env"]).is_file():
        raise ValueError("Client helper or clients_env file missing; check installation and configuration")
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "VLESS_ENV_FILE": cfg["clients_env"]}
    # A credential update spans several services. Ctrl-C must not kill it
    # halfway through. No timeout, automatic retry, or diagnostic cancel hook.
    def wait_for_backend(*_):
        print("Client operation in progress; waiting for the backend to finish.", file=sys.stderr)

    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {sig: signal.signal(sig, wait_for_backend) for sig in signals}
    try:
        result = subprocess.run(["/bin/sh", str(HELPER), action, name],
                                env=env, stdin=subprocess.DEVNULL, start_new_session=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if result.returncode:
        print("Client operation failed. Some changes may already have applied; inspect the backend output "
              "and service state before retrying. No automatic retry was made.", file=sys.stderr)
        return 1
    return 0


def command(cfg, args):
    action = args.client_action
    if action is None:
        return menu(cfg)
    if action == "list":
        rows = names(cfg)
        print(json.dumps({"schema_version": 1, "clients": rows}, indent=2) if args.json else
              "Clients (names only):\n" + "\n".join(rows))
        return 0
    print("\n".join(preview(cfg, action, args.name)), flush=True)
    if not args.run:
        print("PREVIEW ONLY: no changes or links generated. Use --run to execute.")
        return 0
    return execute(cfg, action, args.name)


def menu(cfg):
    """Terminal sub-screen, also opened from the Clients tab. No secret caching."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("Use warden clients list/show/add/rotate/remove in command mode")
    from .tui import panel
    while True:
        try:
            print("\n".join(panel("CLIENTS", names(cfg) + ["", "show: links / refresh subscriptions",
                  "add: new client | rotate: replace VLESS URI | remove: revoke access",
                  "q: return | example: show alice"], 78)))
            request = input("Action and client (show all for all links): ").strip()
            if request.lower() in ("q", "quit", ""):
                return 0
            parts = request.split()
            if len(parts) != 2:
                print("Enter an action and a client name.")
                continue
            action, name = parts
            print("\n".join(panel("PREVIEW", preview(cfg, action, name), 78)))
            if input(f"Type '{action} {name}' to confirm, or Enter to cancel: ").strip() != f"{action} {name}":
                print("Cancelled.")
                continue
            execute(cfg, action, name)
            input("Press Enter to return to clients. ")
        except (EOFError, KeyboardInterrupt):
            return 0
        except (OSError, ValueError) as exc:
            # Do not print parser exceptions containing config/credential text.
            print(str(exc) if type(exc) is ValueError else "Client data unavailable; check paths and permissions.")
            try:
                input("Press Enter to return. ")
            except (EOFError, KeyboardInterrupt):
                return 0
