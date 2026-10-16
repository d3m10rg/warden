#!/usr/bin/env python3
"""Recover a missing client-management env from matching live subscriptions.

Preview by default. No service operations, UUID/token generation or subscription
writes. The installed subscription renderer must reproduce the current payloads.
"""
import argparse
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import tempfile
from urllib.parse import parse_qs, urlsplit


def need(ok, message):
    if not ok:
        raise ValueError(message)


def build(renderer, policy, allow_missing=()):
    users = renderer["read_users"]()
    records = renderer["load_store"]()
    current = {u["name"] for u in users}
    missing = current - set(records)
    need(users and records and not set(records) - current,
         "Client and subscription inventories differ or no subscriptions remain; inspect before recovery")
    need(missing == set(allow_missing),
         "Missing subscription clients must match --allow-missing exactly; inspect inventories before recovery")
    directory = renderer["SUBSCRIPTION_DIR"]
    include = renderer["NGINX_INCLUDE"].read_text(encoding="utf-8")
    config = json.loads(renderer["CONFIG_PATH"].read_text(encoding="utf-8"))
    inbound = [i for i in config["inbounds"] if i.get("tag") == "vless-ws" and i.get("type") == "vless"]
    need(len(inbound) == 1 and inbound[0].get("transport", {}).get("type") == "ws", "Expected one WebSocket VLESS inbound")
    ws_path = inbound[0]["transport"]["path"]
    env, expected_profiles = None, None
    for user in users:
        if user["name"] in missing:
            continue  # Explicitly named new clients have no payload to compare.
        token = records[user["name"]]["token"]
        need(re.fullmatch(r"[a-f0-9]{64}", token), "Invalid subscription token")
        uri = (directory / token).read_text(encoding="utf-8").strip()
        parsed = urlsplit(uri)
        query = parse_qs(parsed.query)
        need(parsed.scheme == "vless" and parsed.username == user["uuid"] and parsed.port == 443,
             "Stored URI does not match current credentials")
        need(query.get("path") == [ws_path], "Stored URI differs from the current WebSocket path")
        prefixes = re.findall(r"location\s*=\s*(/[A-Za-z0-9][A-Za-z0-9._-]*)/" + token + r"\s*\{", include)
        need(len(prefixes) == 1, "Cannot establish the existing subscription prefix")
        candidate = {"VLESS_DOMAIN": parsed.hostname, "VLESS_WS_PATH": ws_path,
                     "VLESS_PROFILE_NAME": "Libertas", "VLESS_SUBSCRIPTION_PREFIX": prefixes[0],
                     "VLESS_HAPP_ROUTING_POLICY": policy.as_posix()}
        need(env is None or env == candidate, "Subscription settings differ between clients")
        env = candidate
        need(renderer["make_vless_uri"](env, user) == uri, "Renderer would change existing VLESS URI settings")
        payload = (directory / (token + ".happ")).read_text(encoding="utf-8").splitlines()
        profiles = []
        for line in payload:
            if line.startswith("happ://routing/add/"):
                profile = json.loads(base64.b64decode(line[len("happ://routing/add/"):], validate=True))
                profile.pop("LastUpdated", None)
                profiles.append(profile)
        need(profiles and [line for line in payload if line.startswith("vless://")] == [uri], "Happ payload differs from generic subscription")
        need(expected_profiles is None or profiles == expected_profiles, "Happ routing differs between clients")
        expected_profiles = profiles
    _, actual = renderer["render_happ_profiles"](env)
    for profile in actual:
        profile.pop("LastUpdated", None)
    need(actual == expected_profiles, "Selected Happ policy does not reproduce the published routing profiles; no file written")
    # Both the shell backend and the installed Python env reader must accept the
    # same literal values. Refuse shell metacharacters instead of guessing escapes.
    for value in env.values():
        need(isinstance(value, str) and value and not any(c in value for c in "'\"\\\n\r\x00"), "Unsupported characters in recovered settings")
    return "# Recovered for client management; not a server installation config.\n" + "".join(
        key + "='" + value + "'\n" for key, value in env.items())


def write_new(path, content):
    """Publish a complete root-private file without overwriting an existing env."""
    fd, temporary = tempfile.mkstemp(prefix=".warden-env-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic, refuses an existing destination/symlink.
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("/root/ravelin-vless-ws.env"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--allow-missing", action="append", default=[], metavar="CLIENT",
                        help="Explicit client without a subscription record; repeat for each missing client")
    args = parser.parse_args()
    try:
        need(os.geteuid() == 0, "Run as root on Ravelin")
        need(all(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) for name in args.allow_missing),
             "Invalid --allow-missing client name")
        need(args.policy.is_absolute() and args.policy.is_file(), "Specify an existing absolute Happ policy path")
        need(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink(), "Output must be an absent absolute path; existing files are never overwritten")
        # Load the already installed, trusted renderer without running its CLI.
        # Only its read/format functions are called. Suppress possible raw errors.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            renderer = runpy.run_path("/usr/local/sbin/ravelin-vless-subscriptions", run_name="warden_env_check")
            content = build(renderer, args.policy, args.allow_missing)
        if args.allow_missing:
            print("Clients without subscription records (not changed): " + ", ".join(sorted(set(args.allow_missing))))
        if args.apply:
            write_new(args.output, content)
            print("Created private client-management env: " + str(args.output))
        else:
            print("MATCH: current credentials, WS path, subscription prefix and Happ routing verified.")
            print("PREVIEW ONLY: would create " + str(args.output) + " (0600); use --apply to create it.")
        print("No services, client UUIDs, subscription tokens or published files changed.")
        return 0
    except (Exception, SystemExit) as exc:
        print(str(exc) if type(exc) is ValueError else "Recovery refused: installed renderer/data unavailable or incompatible. No env created.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
