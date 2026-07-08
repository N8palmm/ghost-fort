#!/usr/bin/env bash
# GHOST FORT — IDENTITY SHIELD INSTALLER
# Elite-level personal identity protection
set -euo pipefail
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
step() { echo -e "\n${CYAN}>>>$*${NC}"; }

echo -e "${GREEN}"
cat << 'BANNER'
  ██╗██████╗ ███████╗███╗   ██╗████████╗██╗████████╗██╗   ██╗
  ██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║╚══██╔══╝╚██╗ ██╔╝
  ██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║   ██║    ╚████╔╝
  ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║     ╚██╔╝
  ██║██████╔╝███████╗██║ ╚████║   ██║   ██║   ██║      ██║
  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝   ╚═╝      ╚═╝
  SHIELD — Elite Identity Protection
BANNER
echo -e "${NC}"

step " 1/4 Installing dependencies"
sudo /opt/ghost-fort/venv/bin/pip install --quiet requests

step " 2/4 Installing Identity Shield"
sudo mkdir -p /var/lib/ghost/identity
sudo chmod 700 /var/lib/ghost/identity
sudo cp identity_shield.py /opt/ghost-fort/
sudo chmod 600 /opt/ghost-fort/identity_shield.py

step " 3/4 Installing systemd service"
sudo tee /etc/systemd/system/ghost-identity.service > /dev/null << 'EOF'
[Unit]
Description=Ghost Fort Identity Shield
After=ghost-fort.service
Wants=ghost-fort.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ghost-fort
ExecStart=/opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/identity_shield.py monitor
Restart=always
RestartSec=10
EnvironmentFile=/etc/environment

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ghost-identity

step " 4/4 Running setup wizard"
sudo /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/identity_shield.py setup

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  GHOST FORT IDENTITY SHIELD INSTALLED${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Commands:"
echo "    Full scan now:    sudo /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/identity_shield.py scan"
echo "    Check status:     sudo /opt/ghost-fort/venv/bin/python3 /opt/ghost-fort/identity_shield.py status"
echo "    Start monitor:    sudo systemctl start ghost-identity"
echo "    Opt-out requests: sudo ls /var/lib/ghost/identity/optout_requests/"
echo "    Google removal:   sudo cat /var/lib/ghost/identity/google_removal_request.txt"
echo ""
