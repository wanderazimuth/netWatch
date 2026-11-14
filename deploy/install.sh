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

# nmap: the daily port scan.
apt-get install -y --no-install-recommends python3-venv nmap

# Ookla's Speedtest CLI: the hourly speed test. One static program, pinned and checked, built for
# this machine; its license is accepted by the --accept-license flag NetWatch runs it with.
case $(uname -m) in
    aarch64) SPEEDTEST_ARCH=aarch64 SPEEDTEST_SHA256=3953d231da3783e2bf8904b6dd72767c5c6e533e163d3742fd0437affa431bd3 ;;
    x86_64)  SPEEDTEST_ARCH=x86_64  SPEEDTEST_SHA256=5690596c54ff9bed63fa3732f818a05dbc2db19ad36ed68f21ca5f64d5cfeeb7 ;;
    *) echo "no Speedtest CLI pinned for $(uname -m)" >&2; exit 1 ;;
esac
SPEEDTEST_URL=https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-$SPEEDTEST_ARCH.tgz
if [[ ! -x /usr/local/bin/speedtest ]]; then
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/speedtest.tgz" "$SPEEDTEST_URL"
    echo "$SPEEDTEST_SHA256  $tmp/speedtest.tgz" | sha256sum -c --quiet
    tar -xzf "$tmp/speedtest.tgz" -C "$tmp" speedtest
    install -m 755 "$tmp/speedtest" /usr/local/bin/speedtest
    rm -rf "$tmp"
fi

[[ -d $APP_DIR/.venv ]] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade "$APP_DIR[deco]"

install -d -m 750 -o root -g netwatch "$CONF_DIR"
if [[ ! -f $CONF_DIR/config.toml ]]; then
    install -m 640 -o root -g netwatch "$APP_DIR/config.example.toml" "$CONF_DIR/config.toml"
    echo "created $CONF_DIR/config.toml -- review it before starting"
fi

for unit in netwatch.service netwatch-web.service netwatch-portscan.service netwatch-portscan.timer             netwatch-speedtest.service netwatch-speedtest.timer netwatch-speedtest.path; do
    install -m 644 "$APP_DIR/deploy/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable netwatch netwatch-web
systemctl enable --now netwatch-portscan.timer netwatch-speedtest.timer netwatch-speedtest.path
systemctl restart netwatch netwatch-web
systemctl --no-pager status netwatch netwatch-web
systemctl --no-pager list-timers netwatch-portscan.timer netwatch-speedtest.timer
