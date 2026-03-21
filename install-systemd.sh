#!/usr/bin/env bash
# Flow2API Host Agent - systemd installer
# Usage: bash install-systemd.sh [install-dir]
set -euo pipefail

INSTALL_DIR="${1:-/opt/flow2api-host-agent}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$(command -v python3)"
SERVICE_USER="muyouzhi"

if [ -z "$PYTHON" ]; then
  echo "python3 not found" >&2
  exit 1
fi

echo "==> Installing to: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "==> Copying files..."
cp -r "$SCRIPT_DIR/scripts" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/web" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/systemd" "$INSTALL_DIR/"
cp -r "$SCRIPT_DIR/docs" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
[ -f "$SCRIPT_DIR/agent.toml" ] && cp "$SCRIPT_DIR/agent.toml" "$INSTALL_DIR/" || cp "$SCRIPT_DIR/agent.example.toml" "$INSTALL_DIR/agent.toml"

echo "==> Creating virtual environment..."
"$PYTHON" -m venv "$INSTALL_DIR/.venv"
VENV_PYTHON="$INSTALL_DIR/.venv/bin/python"
VENV_UVICORN="$INSTALL_DIR/.venv/bin/uvicorn"

echo "==> Installing Python dependencies..."
"$VENV_PYTHON" -m pip install -U pip setuptools wheel >/dev/null
"$VENV_PYTHON" -m pip install -q -r "$INSTALL_DIR/requirements.txt"

echo "==> Ensuring service user..."
id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd -r -M -d /var/lib/flow2api-host-agent -s /usr/sbin/nologin "$SERVICE_USER"

mkdir -p /var/log/flow2api-host-agent
mkdir -p /var/lib/flow2api-host-agent/profile
mkdir -p /var/lib/flow2api-host-agent/runtime
chmod 700 /var/lib/flow2api-host-agent/runtime

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" /var/log/flow2api-host-agent /var/lib/flow2api-host-agent

python3 - <<PY
from pathlib import Path
import re
p = Path("$INSTALL_DIR/agent.toml")
text = p.read_text()
updates = {
    'runtime_dir': '/var/lib/flow2api-host-agent/runtime',
    'home_dir': '/var/lib/flow2api-host-agent',
}
for k, v in updates.items():
    if re.search(rf'^{k}\s*=.*$', text, flags=re.M):
        text = re.sub(rf'^{k}\s*=.*$', f'{k} = "{v}"', text, flags=re.M)
    else:
        text += f'\n{k} = "{v}"\n'
p.write_text(text)
PY

cat > /etc/systemd/system/flow2api-host-agent-browser.service << EOF
[Unit]
Description=Flow2API Host Agent Browser
After=flow2api-host-agent-fluxbox.service
Requires=flow2api-host-agent-fluxbox.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=DISPLAY=:99
Environment=HOME=/var/lib/flow2api-host-agent
Environment=XDG_RUNTIME_DIR=/var/lib/flow2api-host-agent/runtime
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=/bin/sh -lc 'exec /usr/bin/chromium --remote-debugging-port=9223 --user-data-dir=/var/lib/flow2api-host-agent/profile --no-first-run --no-default-browser-check --password-store=basic --disable-dev-shm-usage --disable-gpu --disable-software-rasterizer --disable-session-crashed-bubble --mute-audio https://labs.google/fx/vi/tools/flow'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/flow2api-host-agent.service << EOF
[Unit]
Description=Flow2API Host Agent - Token Auto Refresh Daemon
After=network.target flow2api-host-agent-fluxbox.service flow2api-host-agent-browser.service
Requires=flow2api-host-agent-fluxbox.service flow2api-host-agent-browser.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
Environment=DISPLAY=:99
Environment=HOME=/var/lib/flow2api-host-agent
Environment=XDG_RUNTIME_DIR=/var/lib/flow2api-host-agent/runtime
ExecStart=$VENV_PYTHON $INSTALL_DIR/scripts/agent.py --config $INSTALL_DIR/agent.toml daemon
Restart=always
RestartSec=15
StandardOutput=append:/var/log/flow2api-host-agent/daemon.log
StandardError=append:/var/log/flow2api-host-agent/daemon.log

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/flow2api-host-agent-ui.service << EOF
[Unit]
Description=Flow2API Host Agent - Web UI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
ExecStart=$VENV_UVICORN web.app:app --host 0.0.0.0 --port 38110 --app-dir $INSTALL_DIR
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if [ -f "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.service" ]; then
  cp "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.service" /etc/systemd/system/
fi
if [ -f "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.timer" ]; then
  cp "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.timer" /etc/systemd/system/
fi

echo "==> Cleaning legacy watchdog units..."
for unit in flow2api-host-agent-watchdog.timer flow2api-host-agent-watchdog.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$unit"
done

echo "==> Enabling services..."
systemctl daemon-reload
systemctl enable flow2api-host-agent-browser.service
systemctl enable flow2api-host-agent.service
systemctl enable flow2api-host-agent-ui.service

echo ""
echo "✅ Installation complete!"
echo ""
echo "Services installed:"
echo "  flow2api-host-agent-browser  - browser launcher/service (non-root Chromium)"
echo "  flow2api-host-agent          - token auto-refresh daemon"
echo "  flow2api-host-agent-ui       - Web UI on port 38110"
[ -f "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.timer" ] && echo "  flow2api-host-agent-daily-restart.timer - optional daily maintenance restart"
echo "  (legacy watchdog units are disabled/removed if found)"
echo ""
echo "Important:"
echo "  - Chromium now runs as $SERVICE_USER with sandbox enabled (no --no-sandbox)"
echo "  - Connection Token must be the token string from Flow2API plugin settings, not a URL"
echo "  - novnc_url must use your SERVER IP/domain, not localhost, if accessed from another device"
echo ""
echo "Next steps:"
echo "  1. Edit config: $INSTALL_DIR/agent.toml"
echo "  2. Start browser and login: systemctl start flow2api-host-agent-browser"
echo "  3. Start Web UI: systemctl start flow2api-host-agent-ui"
echo "  4. Start daemon: systemctl start flow2api-host-agent"
[ -f "$INSTALL_DIR/systemd/flow2api-host-agent-daily-restart.timer" ] && echo "  5. (Optional) Enable daily restart: systemctl enable --now flow2api-host-agent-daily-restart.timer"
echo ""
echo "Health check: curl http://127.0.0.1:38110/api/health"
echo "Logs: journalctl -u flow2api-host-agent -f"
