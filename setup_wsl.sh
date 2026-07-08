#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  GHOST FORT v3 — WSL2 / VS CODE SETUP
#  Adapted for WSL2 running through VS Code
#  Run: bash setup_wsl.sh   (no sudo prefix — script handles it)
# ═══════════════════════════════════════════════════════════════

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
step() { echo -e "\n${BOLD}${CYAN}[$1]${NC} $2"; }

echo -e "${GREEN}"
cat << 'BANNER'
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ███████╗ ██████╗ ██████╗ ████████╗
  ╚════██╗ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝
    ███╔╝  ██║  ██║██║   ██║███████╗   ██║       █████╗  ██║   ██║██████╔╝   ██║
  ██╔══╝   ╚═══██╔╝██║   ██║╚════██║   ██║       ██╔══╝  ██║   ██║██╔══██╗   ██║
  ███████╗    ██╔╝ ╚██████╔╝███████║   ██║       ██║     ╚██████╔╝██║  ██║   ██║
  ╚══════╝    ╚═╝   ╚═════╝ ╚══════╝   ╚═╝       ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
  v3 — WSL2 / VS CODE EDITION
BANNER
echo -e "${NC}"

# ── WSL DETECTION ────────────────────────────────────────────
if ! grep -qi microsoft /proc/version 2>/dev/null; then
  warn "This script is designed for WSL2. Detected non-WSL environment."
  read -p "  Continue anyway? (y/N): " ans
  [[ "${ans,,}" != "y" ]] && exit 1
fi

WSL_VERSION=$(uname -r)
log "Running in WSL: $WSL_VERSION"

# ── CHECK SYSTEMD ────────────────────────────────────────────
SYSTEMD_ENABLED=false
if pidof systemd &>/dev/null || [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
  SYSTEMD_ENABLED=true
  log "systemd is running"
else
  warn "systemd not running — will use manual startup mode"
  warn "To enable systemd: see Step 0 instructions in the guide"
fi

# ── 1. PACKAGES ──────────────────────────────────────────────
step "1/7" "Installing packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
  iptables \
  nftables \
  python3 python3-pip python3-venv python3-dev \
  iproute2 curl net-tools sqlite3 \
  libcap2-bin \
  fail2ban \
  libsecret-1-dev \
  dbus-x11 \
  libdbus-1-dev 2>/dev/null || true

# iptables-persistent optional in WSL — may not work fully
sudo apt-get install -y -qq iptables-persistent 2>/dev/null || \
  warn "iptables-persistent not available — rules won't persist across WSL restarts (this is normal in WSL)"

log "Packages installed"

# ── 2. DIRECTORIES ───────────────────────────────────────────
step "2/7" "Creating hardened directories"
DIRS=(
  /var/lib/ghost/cache
  /var/lib/ghost/profiles
  /var/log/ghost
  /etc/ghost-fort
  /opt/ghost-fort/threat
  /opt/ghost-fort/ids
)
for d in "${DIRS[@]}"; do
  sudo mkdir -p "$d"
  sudo chmod 700 "$d"
done
log "Directories created"

# ── 3. PYTHON ENV ────────────────────────────────────────────
step "3/7" "Setting up Python virtual environment"
sudo python3 -m venv /opt/ghost-fort/venv
sudo /opt/ghost-fort/venv/bin/pip install --quiet --upgrade pip
sudo /opt/ghost-fort/venv/bin/pip install --quiet requests

# keyring — try with dbus fallback for WSL
sudo /opt/ghost-fort/venv/bin/pip install --quiet keyring 2>/dev/null || true
sudo /opt/ghost-fort/venv/bin/pip install --quiet secretstorage 2>/dev/null || \
  warn "secretstorage not available — keyring will use env var fallback"

log "Python environment ready"

# ── 4. INSTALL FILES ─────────────────────────────────────────
step "4/7" "Installing Ghost Fort files"
INSTALL_DIR="/opt/ghost-fort"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sudo cp "$SCRIPT_DIR/ghost_fort.py"     $INSTALL_DIR/
sudo cp "$SCRIPT_DIR/intel_engine.py"   $INSTALL_DIR/threat/
sudo cp "$SCRIPT_DIR/ids_engine.py"     $INSTALL_DIR/ids/
sudo cp "$SCRIPT_DIR/alert_notifier.py" $INSTALL_DIR/

sudo touch $INSTALL_DIR/threat/__init__.py
sudo touch $INSTALL_DIR/ids/__init__.py

sudo find $INSTALL_DIR -name "*.py" -exec chmod 600 {} \;
sudo chmod 700 $INSTALL_DIR/ghost_fort.py
log "Files installed"

# ── 5. FIREWALL RULES ────────────────────────────────────────
step "5/7" "Setting up firewall rules"

# WSL note: iptables works but rules don't persist across
# WSL shutdown — the startup script re-applies them each time
sudo iptables -N GHOST_IDS 2>/dev/null || true
sudo iptables -F GHOST_IDS
sudo iptables -C INPUT -j GHOST_IDS 2>/dev/null || \
  sudo iptables -I INPUT 1 -j GHOST_IDS

# IPv6 block
sudo ip6tables -P INPUT   DROP 2>/dev/null || warn "ip6tables not available"
sudo ip6tables -P OUTPUT  DROP 2>/dev/null || true
sudo ip6tables -P FORWARD DROP 2>/dev/null || true

log "Firewall rules applied"

# ── 6. STARTUP METHOD ────────────────────────────────────────
step "6/7" "Configuring startup"

# Create a startup script — used whether systemd is on or off
cat > /tmp/ghost_startup.sh << 'STARTUP'
#!/usr/bin/env bash
# Ghost Fort startup — re-applies firewall rules and starts the service
# Safe to run multiple times

# Re-apply iptables (WSL loses rules on restart)
iptables -N GHOST_IDS 2>/dev/null || true
iptables -F GHOST_IDS
iptables -C INPUT -j GHOST_IDS 2>/dev/null || iptables -I INPUT 1 -j GHOST_IDS
ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

# Start Ghost Fort in background
cd /opt/ghost-fort
nohup /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/ghost_fort.py \
  >> /var/log/ghost/ghost_fort.log 2>&1 &
echo $! > /var/run/ghost-fort.pid
echo "Ghost Fort started (PID: $(cat /var/run/ghost-fort.pid))"
STARTUP
sudo mv /tmp/ghost_startup.sh /opt/ghost-fort/start.sh
sudo chmod 700 /opt/ghost-fort/start.sh

if $SYSTEMD_ENABLED; then
  # Install as systemd service
  cat > /tmp/ghost-fort.service << 'SVCEOF'
[Unit]
Description=Ghost Fort Hardened Security Stack v3
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ghost-fort
ExecStart=/opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/ghost_fort.py
Restart=always
RestartSec=5
MemoryMax=512M
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
  sudo mv /tmp/ghost-fort.service /etc/systemd/system/ghost-fort.service
  sudo systemctl daemon-reload
  sudo systemctl enable ghost-fort
  sudo systemctl start ghost-fort
  log "Ghost Fort installed as systemd service"
else
  # Start manually
  sudo bash /opt/ghost-fort/start.sh
  log "Ghost Fort started in background (no systemd)"
  warn "To start after WSL restart: sudo bash /opt/ghost-fort/start.sh"
fi

# ── 7. FAIL2BAN ──────────────────────────────────────────────
step "7/7" "Configuring fail2ban"

sudo tee /etc/fail2ban/jail.d/ghost-fort.conf > /dev/null << 'F2B'
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 5
bantime  = 3600
findtime = 600

[ghost-fort-ids]
enabled  = true
port     = all
logpath  = /var/log/ghost/ids.log
maxretry = 1
bantime  = 86400
findtime = 3600
filter   = ghost-fort
F2B

sudo tee /etc/fail2ban/filter.d/ghost-fort.conf > /dev/null << 'F2BF'
[Definition]
failregex = ^\s*BLOCKED: <HOST> \|
ignoreregex =
F2BF

sudo service fail2ban restart 2>/dev/null || \
sudo fail2ban-client start 2>/dev/null || \
  warn "fail2ban start failed — run manually: sudo service fail2ban start"

log "fail2ban configured"

# ── LOG ROTATION ─────────────────────────────────────────────
sudo tee /etc/logrotate.d/ghost-fort > /dev/null << 'LR'
/var/log/ghost/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
LR

# ── ALERT SETUP ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}Configure alert channels? (Discord/Email)${NC}"
read -p "  Set up now? (Y/n): " ans
if [[ "${ans,,}" != "n" ]]; then
  sudo /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/alert_notifier.py
fi

# ── DONE ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  GHOST FORT v3 — WSL2 EDITION — READY${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  systemd:  $([ "$SYSTEMD_ENABLED" = true ] && echo "enabled — service auto-starts" || echo "disabled — use start.sh")"
echo ""
echo "  Commands:"
if $SYSTEMD_ENABLED; then
echo "    Status:       sudo systemctl status ghost-fort"
echo "    Restart:      sudo systemctl restart ghost-fort"
echo "    Stop:         sudo systemctl stop ghost-fort"
else
echo "    Start:        sudo bash /opt/ghost-fort/start.sh"
echo "    Stop:         sudo kill \$(cat /var/run/ghost-fort.pid)"
echo "    Status:       cat /var/run/ghost-fort.pid && ps aux | grep ghost_fort"
fi
echo "    Live log:     sudo tail -f /var/log/ghost/ghost_fort.log"
echo "    Block log:    sudo tail -f /var/log/ghost/ids.log"
echo "    Bans:         sudo iptables -L GHOST_IDS -n"
echo "    JSON status:  sudo cat /var/lib/ghost/status.json"
echo "    Test alert:   sudo /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/alert_notifier.py"
echo ""
