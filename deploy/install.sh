#!/usr/bin/env bash
# Install or update NetWatch on the Pi. Run from a clone at /opt/netwatch:
#   sudo bash /opt/netwatch/deploy/install.sh
set -euo pipefail

APP_DIR=/opt/netwatch
CONF_DIR=/etc/netwatch

if [[ $EUID -ne 0 ]]; then
    echo "run with sudo" >&2
    exit 1
fi

id netwatch &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin netwatch

apt-get install -y --no-install-recommends python3-venv

[[ -d $APP_DIR/.venv ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade "$APP_DIR"

install -d -m 750 -o root -g netwatch "$CONF_DIR"
if [[ ! -f $CONF_DIR/config.toml ]]; then
    install -m 640 -o root -g netwatch "$APP_DIR/config.example.toml" "$CONF_DIR/config.toml"
    echo "created $CONF_DIR/config.toml -- review it before starting"
fi

install -m 644 "$APP_DIR/deploy/netwatch.service" /etc/systemd/system/netwatch.service
systemctl daemon-reload
systemctl enable netwatch
systemctl restart netwatch
systemctl --no-pager status netwatch
