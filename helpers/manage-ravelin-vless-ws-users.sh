#!/bin/sh
set -eu
umask 077

# Manage per-user VLESS credentials in the loopback-only sing-box inbound
# installed by install-ravelin-vless-ws.sh. The Nginx virtual host is never
# changed here.

ENV_FILE="${VLESS_ENV_FILE:-/root/ravelin-vless-ws.env}"
SINGBOX_CONFIG=/etc/sing-box/vless-ws.json
SERVICE=sing-box-vless-ws.service
LOCK_FILE=/run/lock/ravelin-vless-ws-users.lock
SUBSCRIPTION_HELPER=/usr/local/sbin/ravelin-vless-subscriptions
TRAFFIC_ACCOUNTING_HELPER=/usr/local/sbin/ravelin-vless-traffic-accounting
POLICY_LOCK=/run/lock/ravelin-policy-routing.lock

usage() {
    cat <<'EOF'
Usage:
  manage-ravelin-vless-ws-users.sh list
  manage-ravelin-vless-ws-users.sh show <user|all>
  manage-ravelin-vless-ws-users.sh add <user>
  manage-ravelin-vless-ws-users.sh rotate <user>
  manage-ravelin-vless-ws-users.sh remove <user>

Commands add and rotate print a new vless:// URI, generic HTTPS subscription,
and Happ HTTPS subscription. Give Happ users only the URL ending in /happ.
rotate revokes the old URI while keeping the user's subscription URL stable.
Set VLESS_ENV_FILE to use an env file other than /root/ravelin-vless-ws.env.
EOF
}

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root." >&2
    exit 1
fi

ACTION="${1:-}"
USER_NAME="${2:-}"
case "$ACTION" in
    list)
        [ -z "$USER_NAME" ] || { usage >&2; exit 1; }
        ;;
    show)
        [ -n "$USER_NAME" ] || { usage >&2; exit 1; }
        ;;
    add|rotate|remove)
        [ -n "$USER_NAME" ] || { usage >&2; exit 1; }
        case "$USER_NAME" in
            all|*[!A-Za-z0-9._-]*|"")
                echo "User name may contain only letters, digits, dot, underscore and dash." >&2
                exit 1
                ;;
        esac
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac

for cmd in sing-box systemctl python3 flock nginx; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "Missing command: $cmd" >&2
        exit 1
    }
done
[ -f "$SINGBOX_CONFIG" ] || { echo "Missing sing-box config: $SINGBOX_CONFIG" >&2; exit 1; }
[ -x "$SUBSCRIPTION_HELPER" ] || {
    echo "Missing subscription helper: $SUBSCRIPTION_HELPER. Re-run the VLESS installer first." >&2
    exit 1
}

# shellcheck disable=SC1090
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
VLESS_DOMAIN="${VLESS_DOMAIN:-}"
VLESS_WS_PATH="${VLESS_WS_PATH:-}"
VLESS_PROFILE_NAME="${VLESS_PROFILE_NAME:-Libertas}"

require_client_settings() {
    [ -n "$VLESS_DOMAIN" ] || { echo "Missing VLESS_DOMAIN in $ENV_FILE" >&2; exit 1; }
    [ "$VLESS_PROFILE_NAME" = Libertas ] || { echo "VLESS_PROFILE_NAME must be Libertas in $ENV_FILE" >&2; exit 1; }
    case "$VLESS_WS_PATH" in
        /?*) ;;
        *) echo "Missing or invalid VLESS_WS_PATH in $ENV_FILE" >&2; exit 1 ;;
    esac
}

show_uri() {
    requested="$1"
    require_client_settings
    python3 - "$SINGBOX_CONFIG" "$requested" "$VLESS_DOMAIN" "$VLESS_WS_PATH" "$VLESS_PROFILE_NAME" <<'PY'
import json
import pathlib
import sys
import urllib.parse

config_path, requested, domain, path, profile = sys.argv[1:]
config = json.loads(pathlib.Path(config_path).read_text(encoding="utf-8"))
inbound = next(
    item for item in config["inbounds"]
    if item.get("tag") == "vless-ws" and item.get("type") == "vless"
)
users = inbound["users"]
if requested == "all":
    selected = users
else:
    selected = [item for item in users if item.get("name") == requested]
    if not selected:
        raise SystemExit(f"Unknown user: {requested}")

for user in selected:
    query = urllib.parse.urlencode({
        "encryption": "none",
        "security": "tls",
        "sni": domain,
        "alpn": "http/1.1",
        "fp": "chrome",
        "type": "ws",
        "host": domain,
        "path": path,
    })
    name = f"{profile}_{user['name']}"
    uri = f"vless://{user['uuid']}@{domain}:443?{query}#{urllib.parse.quote(name, safe='')}"
    print(f"{user['name']}\t{uri}")
PY
}

sync_subscriptions() {
    "$SUBSCRIPTION_HELPER" sync "" "$ENV_FILE"
    nginx -t
    systemctl reload nginx
}

sync_traffic_accounting() {
    # This optional helper is installed by the Grafana/Prometheus monitoring
    # package. It adds only per-user egress marks and nft counters; normal
    # installations continue to work unchanged when monitoring is absent.
    [ -x "$TRAFFIC_ACCOUNTING_HELPER" ] || return 0
    "$TRAFFIC_ACCOUNTING_HELPER" sync
}

verify_protected_config() {
    # Registry-v2 uses one stable source across all channels. Never restart
    # sing-box with a legacy tunnel-specific source from an old accounting helper.
    python3 - "$SINGBOX_CONFIG" "${1:-}" <<'PY'
import json
import pathlib
import sys

def protected(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return {o["tag"]: o for o in data.get("outbounds", [])
            if o.get("type") == "direct" and o.get("tag", "").startswith("forpost")}

current = protected(sys.argv[1])
if not current or any(o.get("inet4_bind_address") != "10.78.254.2" for o in current.values()):
    raise SystemExit("Protected VLESS outbounds must retain stable source 10.78.254.2; check the installed accounting helper/environment.")
if sys.argv[2]:
    previous = protected(sys.argv[2])
    if any(current[tag].get("routing_mark") != previous[tag].get("routing_mark") for tag in current.keys() & previous.keys()):
        raise SystemExit("Existing VLESS accounting marks changed; refusing to restart sing-box.")
PY
}

show_subscription() {
    "$SUBSCRIPTION_HELPER" show "$1" "$ENV_FILE"
}

show_happ_subscription() {
    "$SUBSCRIPTION_HELPER" show-happ "$1" "$ENV_FILE"
}

# sync/list/show also update subscription files, so every action takes the
# same lock as credential mutations.
mkdir -p "$(dirname "$LOCK_FILE")"
# Match forpostctl's mutation lock; its controller continues independently
# after this short explicit operation. Passive list/show need no policy lock.
if [ "$ACTION" != list ] && [ "$ACTION" != show ]; then
    exec 8>"$POLICY_LOCK"
    flock -w 30 8 || { echo "Policy operation busy; no client changes made." >&2; exit 1; }
fi
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "Another VLESS user management operation is running." >&2; exit 1; }

if [ "$ACTION" = list ]; then
    sync_subscriptions
    echo "== users =="
    python3 - "$SINGBOX_CONFIG" <<'PY'
import json
import pathlib
import sys

config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
inbound = next(
    item for item in config["inbounds"]
    if item.get("tag") == "vless-ws" and item.get("type") == "vless"
)
for user in inbound["users"]:
    print(f"{user['name']}\t{user['uuid']}")
PY
    echo "== generic subscription URLs =="
    "$SUBSCRIPTION_HELPER" list "" "$ENV_FILE"
    echo "== Happ subscription URLs =="
    "$SUBSCRIPTION_HELPER" list-happ "" "$ENV_FILE"
    exit 0
fi

if [ "$ACTION" = show ]; then
    sync_subscriptions
    show_uri "$USER_NAME"
    if [ "$USER_NAME" = all ]; then
        echo "== generic subscription URLs =="
        "$SUBSCRIPTION_HELPER" list "" "$ENV_FILE"
        echo "== Happ subscription URLs =="
        "$SUBSCRIPTION_HELPER" list-happ "" "$ENV_FILE"
    else
        echo "== generic subscription URL =="
        show_subscription "$USER_NAME"
        echo "== Happ subscription URL =="
        show_happ_subscription "$USER_NAME"
    fi
    exit 0
fi

systemctl is-active --quiet "$SERVICE" || {
    echo "$SERVICE is not active; resolve that before changing credentials." >&2
    exit 1
}

# Fail before changing credentials if URI settings cannot be rendered.
require_client_settings
verify_protected_config

candidate="$(mktemp)"
trap 'rm -f "$candidate"' EXIT HUP INT TERM

python3 - "$SINGBOX_CONFIG" "$candidate" "$ACTION" "$USER_NAME" <<'PY'
import json
import pathlib
import sys
import uuid

source_path, candidate_path, action, name = sys.argv[1:]
source = pathlib.Path(source_path)
config = json.loads(source.read_text(encoding="utf-8"))
try:
    inbound = next(
        item for item in config["inbounds"]
        if item.get("tag") == "vless-ws" and item.get("type") == "vless"
    )
    users = inbound["users"]
except (KeyError, StopIteration, TypeError) as exc:
    raise SystemExit(f"Invalid VLESS inbound in {source_path}: {exc}")

if not isinstance(users, list) or not users:
    raise SystemExit("VLESS user list is empty or invalid")
if any(not isinstance(item, dict) or not item.get("name") or not item.get("uuid") for item in users):
    raise SystemExit("VLESS user list contains an invalid user")
if len({item["name"] for item in users}) != len(users):
    raise SystemExit("VLESS user list contains duplicate names")
if len(name) > 64:
    raise SystemExit("User name must not be longer than 64 characters")

index = next((i for i, item in enumerate(users) if item["name"] == name), None)
if action == "add":
    if index is not None:
        raise SystemExit(f"User already exists: {name}")
    users.append({"name": name, "uuid": str(uuid.uuid4())})
elif action == "rotate":
    if index is None:
        raise SystemExit(f"Unknown user: {name}")
    users[index]["uuid"] = str(uuid.uuid4())
elif action == "remove":
    if index is None:
        raise SystemExit(f"Unknown user: {name}")
    if len(users) == 1:
        raise SystemExit("Refusing to remove the last user; disable the service explicitly if decommissioning it")
    users.pop(index)
else:
    raise SystemExit(f"Unsupported action: {action}")

pathlib.Path(candidate_path).write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
PY

sing-box check -c "$candidate"

backup_dir="$(mktemp -d "/root/ravelin-vless-ws-users-backup-$(date +%Y%m%d-%H%M%S)-XXXXXX")"
cp -a "$SINGBOX_CONFIG" "$backup_dir/vless-ws.json"
install -m 0600 "$candidate" "$SINGBOX_CONFIG"

if ! sync_traffic_accounting; then
    cp -a "$backup_dir/vless-ws.json" "$SINGBOX_CONFIG"
    echo "Traffic accounting did not synchronize; restored $SINGBOX_CONFIG from $backup_dir." >&2
    exit 1
fi

if ! verify_protected_config "$backup_dir/vless-ws.json"; then
    cp -a "$backup_dir/vless-ws.json" "$SINGBOX_CONFIG"
    echo "Protected VLESS settings changed during accounting sync; config restored, sing-box not restarted. Inspect accounting state before retrying." >&2
    exit 1
fi

if ! systemctl restart "$SERVICE" || ! systemctl is-active --quiet "$SERVICE"; then
    cp -a "$backup_dir/vless-ws.json" "$SINGBOX_CONFIG"
    sync_traffic_accounting || true
    # A failed helper must not undo the restored protected source/marks.
    if ! verify_protected_config "$backup_dir/vless-ws.json"; then
        cp -a "$backup_dir/vless-ws.json" "$SINGBOX_CONFIG"
    fi
    systemctl restart "$SERVICE" || true
    echo "Service did not restart; restored $SINGBOX_CONFIG from $backup_dir." >&2
    exit 1
fi

sync_subscriptions

case "$ACTION" in
    add)
        echo "User added: $USER_NAME"
        echo "Backup: $backup_dir"
        show_uri "$USER_NAME"
        echo "== generic subscription URL =="
        show_subscription "$USER_NAME"
        echo "== Happ subscription URL =="
        show_happ_subscription "$USER_NAME"
        ;;
    rotate)
        echo "User credentials rotated: $USER_NAME (the previous URI is revoked)."
        echo "Backup: $backup_dir"
        show_uri "$USER_NAME"
        echo "== generic subscription URL =="
        show_subscription "$USER_NAME"
        echo "== Happ subscription URL =="
        show_happ_subscription "$USER_NAME"
        ;;
    remove)
        echo "User removed and access revoked: $USER_NAME"
        echo "Backup: $backup_dir"
        ;;
esac
