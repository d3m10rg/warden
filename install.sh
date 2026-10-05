#!/bin/sh
# Explicit local installation only; touches Warden-owned paths/services.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root (sudo sh install.sh).' >&2
    exit 1
fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "$source_dir" = /opt/warden ]; then
    echo 'Run the installer from a separate checkout, not /opt/warden.' >&2
    exit 1
fi
python3 -c 'import sys, curses, sqlite3; assert sys.version_info >= (3, 9), "Python >=3.9 required"'
for tool in ip systemctl ss; do
    command -v "$tool" >/dev/null
done
if ! command -v awg >/dev/null && ! command -v wg >/dev/null; then
    echo 'awg or wg is required; no dependencies were installed.' >&2
    exit 1
fi
if [ -L /opt/warden ] || [ -L /etc/warden ] || [ -L /var/lib/warden ]; then
    echo 'Refusing symlink installation/state directory.' >&2
    exit 1
fi
if [ -d /opt/warden ] && [ ! -f /opt/warden/.warden-install ]; then
    echo '/opt/warden exists without the Warden installation marker; refusing overwrite.' >&2
    exit 1
fi
if [ -e /usr/local/bin/warden ] && [ "$(readlink /usr/local/bin/warden || true)" != /opt/warden/bin/warden ]; then
    echo '/usr/local/bin/warden already exists and is not owned by this installer.' >&2
    exit 1
fi
# Validate source before stopping an already installed Warden collector.
python3 -B "$source_dir/bin/warden" --demo status --json >/dev/null
systemctl stop warden-collector.service 2>/dev/null || true
install -d -m 0755 /opt/warden /opt/warden/warden /opt/warden/bin
install -m 0644 "$source_dir"/warden/*.py /opt/warden/warden/
install -m 0755 "$source_dir/bin/warden" /opt/warden/bin/warden
python3 -B /opt/warden/bin/warden --version > /opt/warden/.warden-install
install -d -m 0700 /etc/warden /var/lib/warden
if [ ! -e /etc/warden/config.json ]; then
    install -m 0600 "$source_dir/config.example.json" /etc/warden/config.json
fi
install -m 0644 "$source_dir/systemd/warden-collector.service" /etc/systemd/system/warden-collector.service
ln -sfn /opt/warden/bin/warden /usr/local/bin/warden
systemctl daemon-reload
systemctl enable --now warden-collector.service
printf '%s\n' 'Warden installed. Inspect: systemctl status warden-collector --no-pager' 'Open: warden'
