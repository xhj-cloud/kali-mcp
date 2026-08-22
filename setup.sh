#!/usr/bin/env bash
# =============================================================================
# Kali MCP Server — One-click setup for Kali / Debian
# =============================================================================
# Usage:
#   chmod +x setup.sh
#   sudo ./setup.sh                        # Full install
#   sudo ./setup.sh --skip-packages        # Skip apt, just venv + config
#   sudo ./setup.sh --skip-venv            # Skip venv, just packages + config
#   sudo ./setup.sh --tool-level full      # Install optional pentest/attack pkgs
# =============================================================================

set -euo pipefail

# -- Colors --
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner()  { echo -e "\n${GREEN}========================================${NC}"; }
step()    { echo -e "${YELLOW}[$1]${NC} ${BOLD}$2${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()     { echo -e "  ${RED}✗${NC} $1"; }

# -- Flags --
SKIP_PACKAGES=false
SKIP_VENV=false
TOOL_LEVEL="basic"   # basic | pentest | full

for arg in "$@"; do
    case "$arg" in
        --skip-packages) SKIP_PACKAGES=true ;;
        --skip-venv)     SKIP_VENV=true ;;
        --tool-level)    TOOL_LEVEL="$2"; shift ;;
        --tool-level=*)  TOOL_LEVEL="${arg#*=}" ;;
        --help|-h)
            echo "Usage: sudo ./setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-packages   Skip system package install (apt)"
            echo "  --skip-venv       Skip Python venv creation"
            echo "  --tool-level LVL  basic | pentest | full  (default: basic)"
            exit 0
            ;;
    esac
    shift 2>/dev/null || true
done

banner
echo -e "${GREEN}  Kali MCP Server — Setup${NC}"
banner
echo ""

# ===========================================================================
# 1. Pre-flight checks
# ===========================================================================

if ! command -v apt &>/dev/null; then
    err "apt not found — this script requires Kali / Debian"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    warn "Not running as root — will use sudo where needed"
    SUDO="sudo"
else
    SUDO=""
fi

# Detect VM / environment
if systemd-detect-virt --quiet 2>/dev/null; then
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    warn "Detected virtualisation: ${CYAN}${VIRT_TYPE}${NC}"
    if [ "$VIRT_TYPE" = "vmware" ] || [ "$VIRT_TYPE" = "kvm" ] || [ "$VIRT_TYPE" = "oracle" ]; then
        echo -e "     Make sure the VM network adapter is set to ${BOLD}BRIDGED${NC} mode,"
        echo -e "     otherwise Cherry Studio won't be able to reach the MCP server."
    fi
else
    ok "Running on physical hardware"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# ===========================================================================
# 2. System packages
# ===========================================================================

if [ "$SKIP_PACKAGES" = false ]; then

# --- Base packages (always needed) ---
BASE_PKGS=(
    nmap
    arp-scan
    traceroute
    mtr
    dnsutils
    whois
    tcpdump
    nethogs
    curl
    iproute2
    openssl        # ssl_cert_check — s_client/x509 解析（Kali 预装，Debian 需显式安装）
    nftables       # firewall_rules — `nft list ruleset` 只读审计
    iptables       # firewall_rules — filter/nat 表规则查看
    python3
    python3-pip
    python3-venv
    python3-dev
    libcap2-bin
)

# --- Pentest packages (--tool-level pentest|full) ---
PENTEST_PKGS=(
    whatweb
    nikto
    gobuster
    enum4linux
    hydra
    nuclei
    ffuf
    dnsrecon
    snmp
    onesixtyone
    seclists
    exploitdb
    apache2-utils   # ab — http_load_test
)

# Auto-download nuclei templates (not in apt)
_nuclei_setup() {
    if command -v nuclei &>/dev/null; then
        echo -e "  Downloading nuclei templates..."
        nuclei -ut -silent 2>&1 | tail -1 || true
        ok "nuclei templates ready"
    fi
}

# --- Attack packages (--tool-level full) ---
ATTACK_PKGS=(
    sqlmap
    wpscan
    metasploit-framework
    aircrack-ng
    john
    crackmapexec
    netcat-openbsd
    dsniff
    yersinia
    tshark
    reaver
    ettercap-text-only
    bettercap
    sslstrip
)

step "1/6" "Installing system packages (level: ${TOOL_LEVEL})..."

$SUDO apt update -qq

echo -e "  Installing base packages..."
$SUDO apt install -y -qq "${BASE_PKGS[@]}" 2>&1 | tail -1
ok "Base packages ($(echo "${BASE_PKGS[@]}" | wc -w) pkgs)"

if [ "$TOOL_LEVEL" = "pentest" ] || [ "$TOOL_LEVEL" = "full" ]; then
    echo -e "  Installing pentest packages..."
    $SUDO apt install -y -qq "${PENTEST_PKGS[@]}" 2>&1 | tail -1
    ok "Pentest packages ($(echo "${PENTEST_PKGS[@]}" | wc -w) pkgs)"
    _nuclei_setup
fi

if [ "$TOOL_LEVEL" = "full" ]; then
    echo -e "  Installing attack packages..."
    $SUDO apt install -y -qq "${ATTACK_PKGS[@]}" 2>&1 | tail -1
    ok "Attack packages ($(echo "${ATTACK_PKGS[@]}" | wc -w) pkgs)"
fi

else
    step "1/6" "Skipping packages (--skip-packages)"
fi

# ===========================================================================
# 3. Set capabilities (run tools without root)
# ===========================================================================

step "2/6" "Configuring tool capabilities..."

_set_cap() {
    local bin=$1
    if command -v "$bin" &>/dev/null; then
        $SUDO setcap cap_net_raw,cap_net_admin+eip "$(command -v "$bin")" 2>/dev/null && \
            ok "cap_net_raw+admin → ${bin}" || \
            warn "Could not set capabilities for ${bin}"
    fi
}

_set_cap tcpdump
_set_cap arp-scan
_set_cap nethogs

# ===========================================================================
# 4. Python venv
# ===========================================================================

if [ "$SKIP_VENV" = false ]; then

step "3/6" "Creating Python virtual environment..."

if [ -d "$VENV_DIR" ]; then
    warn "venv already exists at ${VENV_DIR}"
    read -rp "  Recreate? [y/N]: " RECREATE
    if [[ "$RECREATE" =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
        ok "venv recreated"
    fi
else
    python3 -m venv "$VENV_DIR"
    ok "venv created at ${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo -e "  Installing Python dependencies..."
pip install --upgrade pip -q 2>&1 | tail -1
pip install -r "$SCRIPT_DIR/requirements.txt" -q 2>&1 | tail -1
ok "Python deps installed"

else
    step "3/6" "Skipping venv (--skip-venv)"
    # Still source if it exists
    if [ -f "$VENV_DIR/bin/activate" ]; then
        source "$VENV_DIR/bin/activate"
    fi
fi

# ===========================================================================
# 5. Environment configuration
# ===========================================================================

step "4/6" "Configuring environment..."

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"

    AUTH_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null || echo "")
    if [ -n "$AUTH_TOKEN" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s/^AUTH_TOKEN=$/AUTH_TOKEN=$AUTH_TOKEN/" "$SCRIPT_DIR/.env"
        else
            sed -i "s/^AUTH_TOKEN=$/AUTH_TOKEN=$AUTH_TOKEN/" "$SCRIPT_DIR/.env"
        fi
        echo -e "  Auth token: ${CYAN}${AUTH_TOKEN}${NC}"
    fi
    ok ".env created from .env.example"
else
    ok ".env already exists, skipping"
fi

# Auto-configure tool levels if not already set
if grep -q "^PENTEST_ENABLED=false" "$SCRIPT_DIR/.env" 2>/dev/null; then
    if [ "$TOOL_LEVEL" = "pentest" ] || [ "$TOOL_LEVEL" = "full" ]; then
        sed -i "s/^PENTEST_ENABLED=false/PENTEST_ENABLED=true/" "$SCRIPT_DIR/.env"
        ok "PENTEST_ENABLED=true (matched --tool-level)"
    fi
fi
if grep -q "^ATTACK_ENABLED=false" "$SCRIPT_DIR/.env" 2>/dev/null; then
    if [ "$TOOL_LEVEL" = "full" ]; then
        sed -i "s/^ATTACK_ENABLED=false/ATTACK_ENABLED=true/" "$SCRIPT_DIR/.env"
        ok "ATTACK_ENABLED=true (matched --tool-level)"
    fi
fi

# ===========================================================================
# 6. Monitor state directory
# ===========================================================================

step "5/6" "Creating monitor state directory..."

MONITOR_DIR="$HOME/.kali-mcp/monitor"
mkdir -p "$MONITOR_DIR" 2>/dev/null || {
    MONITOR_DIR="/var/lib/kali-mcp/monitor"
    $SUDO mkdir -p "$MONITOR_DIR"
    $SUDO chown "$(whoami):$(whoami)" "$MONITOR_DIR" 2>/dev/null || true
}
ok "Monitor state: ${MONITOR_DIR}"

# ===========================================================================
# 7. systemd service
# ===========================================================================

step "6/6" "systemd service..."

SYSTEMD_SERVICE=$(
    cat <<SYSTEMD
[Unit]
Description=Kali MCP Server — AI-powered network tools
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR
Environment=HOME=$HOME
Environment=PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=src
EnvironmentFile=-$SCRIPT_DIR/.env
ExecStart=$VENV_DIR/bin/python -m kali_mcp.server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD
)

echo ""
echo -e "${CYAN}--- Proposed systemd service ---${NC}"
echo "$SYSTEMD_SERVICE"
echo -e "${CYAN}--------------------------------${NC}"
echo ""

read -rp "Install systemd service for auto-start on boot? [y/N]: " INSTALL
if [[ "$INSTALL" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/kali-mcp.service"

    # Check for existing service
    if [ -f "$SERVICE_FILE" ]; then
        warn "Service file already exists"
        read -rp "  Overwrite? [y/N]: " OVERWRITE
        if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
            ok "Kept existing service file"
        fi
    fi

    if [ ! -f "$SERVICE_FILE" ] || [[ "$OVERWRITE" =~ ^[Yy]$ ]]; then
        echo "$SYSTEMD_SERVICE" | $SUDO tee "$SERVICE_FILE" > /dev/null
    fi

    $SUDO systemctl daemon-reload
    $SUDO systemctl enable kali-mcp --now 2>/dev/null || {
        $SUDO systemctl enable kali-mcp
        $SUDO systemctl start kali-mcp
    }

    sleep 1
    if systemctl is-active --quiet kali-mcp; then
        ok "systemd service running ✓"
    else
        warn "Service may not have started. Check:"
        echo -e "    ${BOLD}sudo journalctl -u kali-mcp -n 20${NC}"
    fi
else
    ok "Skipped systemd — manual start:"
    echo -e "    ${BOLD}PYTHONPATH=src $VENV_DIR/bin/python -m kali_mcp.server${NC}"
fi

# ===========================================================================
# Done
# ===========================================================================

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "YOUR_KALI_IP")
TOOL_COUNT=$(grep -c "^\"" src/kali_mcp/tools.py 2>/dev/null || echo "?")
MONITOR_COUNT=3

banner
echo -e "${GREEN}  Setup complete!${NC}"
banner
echo ""
echo -e "  ${BOLD}Kali IP:${NC}       ${CYAN}${HOST_IP}${NC}"
echo -e "  ${BOLD}MCP URL:${NC}      ${CYAN}http://${HOST_IP}:8000/mcp${NC}"
echo -e "  ${BOLD}Tool level:${NC}   ${TOOL_LEVEL}"
echo ""
echo -e "  Connect Cherry Studio → MCP → Streamable HTTP:"
echo -e "    ${BOLD}http://${HOST_IP}:8000/mcp${NC}"
echo ""
echo -e "  Quick commands:"
echo -e "    Enable pentest:    ${BOLD}sed -i 's/PENTEST_ENABLED=.*/PENTEST_ENABLED=true/' .env${NC}"
echo -e "    Enable attacks:    ${BOLD}sed -i 's/ATTACK_ENABLED=.*/ATTACK_ENABLED=true/' .env${NC}"
echo -e "    Restart service:   ${BOLD}sudo systemctl restart kali-mcp${NC}"
echo -e "    View logs:         ${BOLD}sudo journalctl -u kali-mcp -f${NC}"
echo -e "    Test endpoint:     ${BOLD}curl http://${HOST_IP}:8000/mcp${NC}"
echo ""
