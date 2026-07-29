#!/usr/bin/env bash
# =============================================================================
# Kali MCP Server — One-click setup for Kali Linux
#
# This script:
#  1. Installs required Kali system packages (nmap, tcpdump, etc.)
#  2. Creates a Python venv
#  3. Installs Python dependencies
#  4. Optionally installs systemd service for auto-start
#
# Usage (on Kali host):
#   chmod +x setup.sh
#   sudo ./setup.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Kali MCP Server — Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# ---------- 1. Check we're on Kali / Debian ----------
if ! command -v apt &>/dev/null; then
    echo -e "${RED}Error: apt not found. This script requires Kali/Debian.${NC}"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Not running as root. Will use sudo for apt/systemd steps.${NC}"
    SUDO="sudo"
else
    SUDO=""
fi

# ---------- 2. System packages ----------
echo -e "${YELLOW}[1/5] Installing system packages...${NC}"

PACKAGES=(
    nmap            # Port scanning
    arp-scan        # ARP network discovery
    traceroute      # Path tracing
    mtr             # Combined ping+traceroute
    dnsutils        # dig, nslookup
    whois           # WHOIS lookups
    tcpdump         # Packet capture
    curl            # HTTP requests
    iproute2        # ss, ip commands
    python3         # Python runtime
    python3-pip     # Package manager
    python3-venv    # Virtual environments
)

$SUDO apt update -qq
$SUDO apt install -y "${PACKAGES[@]}"

echo -e "${GREEN}✓ System packages installed${NC}"

# ---------- 3. Allow tcpdump without root (optional) ----------
echo -e "${YELLOW}[2/5] Configuring tcpdump capabilities...${NC}"
if command -v setcap &>/dev/null; then
    $SUDO setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || {
        echo -e "${YELLOW}⚠ Could not set tcpdump capabilities (non-fatal). Run tcpdump with sudo.${NC}"
    }
else
    echo -e "${YELLOW}⚠ setcap not found. Run tcpdump tools with sudo.${NC}"
fi

# ---------- 4. Python venv ----------
echo -e "${YELLOW}[3/5] Creating Python virtual environment...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt"

echo -e "${GREEN}✓ Python venv created at $VENV_DIR${NC}"

# ---------- 5. Create .env if not exists ----------
echo -e "${YELLOW}[4/5] Configuring environment...${NC}"

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"

    # Generate a random auth token
    AUTH_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    # Use sed that works on both macOS and Linux
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^AUTH_TOKEN=$/AUTH_TOKEN=$AUTH_TOKEN/" "$SCRIPT_DIR/.env"
    else
        sed -i "s/^AUTH_TOKEN=$/AUTH_TOKEN=$AUTH_TOKEN/" "$SCRIPT_DIR/.env"
    fi

    echo -e "${GREEN}✓ .env created with random auth token${NC}"
    echo -e "${YELLOW}  Auth token: $AUTH_TOKEN${NC}"
else
    echo -e "${YELLOW}  .env already exists, skipping${NC}"
fi

# ---------- 6. systemd service (optional) ----------
echo -e "${YELLOW}[5/5] systemd service setup...${NC}"

read -rp "Install systemd service for auto-start on boot? [y/N]: " INSTALL_SERVICE
if [[ "$INSTALL_SERVICE" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/kali-mcp.service"
    $SUDO tee "$SERVICE_FILE" > /dev/null <<SYSTEMD
[Unit]
Description=Kali MCP Server — AI-powered network tools
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
Environment=PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=src
ExecStart=$VENV_DIR/bin/python -m kali_mcp.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable kali-mcp
    $SUDO systemctl start kali-mcp

    echo -e "${GREEN}✓ systemd service installed and started${NC}"
    echo -e "  Status: sudo systemctl status kali-mcp"
    echo -e "  Logs:   sudo journalctl -u kali-mcp -f"
else
    echo -e "${YELLOW}  Skipped systemd service${NC}"
fi

# ---------- Done ----------
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Quick start:"
echo -e "  cd $SCRIPT_DIR"
echo -e "  source .venv/bin/activate"
echo -e "  python -m kali_mcp.server --transport http"
echo ""
echo -e "Cherry Studio / Claude Desktop config:"
echo -e "  Add MCP server at: ${YELLOW}http://$(hostname -I | awk '{print $1}'):8000/mcp${NC}"
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_KALI_IP")
if [ -n "$HOST_IP" ]; then
    echo -e "  Kali host IP: ${YELLOW}$HOST_IP${NC}"
fi
