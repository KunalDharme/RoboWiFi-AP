#!/usr/bin/env bash
# setup.sh - Setup script for fake_ap.sh
# Installs dependencies and prepares system for running fake access point
#
# Usage:
#   sudo ./setup.sh [--with-wpe]
#     --with-wpe    Install hostapd-wpe for password capture (optional)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
  echo -e "\n${BLUE}==>${NC} $*"
}

# Parse arguments
INSTALL_WPE=false
for arg in "$@"; do
  if [[ "$arg" == "--with-wpe" ]]; then
    INSTALL_WPE=true
  elif [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
    cat <<EOF
${GREEN}Fake Access Point Setup Script${NC}

This script installs and configures all dependencies needed to run fake_ap.sh

Usage:
  sudo $0 [OPTIONS]

Options:
  --with-wpe    Install hostapd-wpe for WPA2 password capture
  --help, -h    Show this help message

What this script does:
  1. Checks system requirements
  2. Installs required packages (hostapd, dnsmasq, etc.)
  3. Optionally installs hostapd-wpe for password capture
  4. Verifies wireless interface capabilities
  5. Configures system settings
  6. Creates necessary directories and permissions

Requirements:
  - Debian/Ubuntu-based system (or compatible)
  - Root/sudo access
  - Wireless interface with AP mode support

Note: This tool should only be used on networks you own or have permission to test.
EOF
    exit 0
  fi
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root: sudo $0"
  exit 1
fi

# Banner
echo -e "${GREEN}"
cat <<'EOF'
╔═══════════════════════════════════════════════════╗
║                                                   ║
║       Fake Access Point Setup Script             ║
║       Installing Dependencies & Configuration    ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Detect OS
log_step "Detecting operating system..."
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_NAME=$NAME
  OS_VERSION=$VERSION_ID
  log_info "Detected: $OS_NAME $OS_VERSION"
else
  log_error "Cannot detect OS. /etc/os-release not found."
  exit 1
fi

# Check if Debian/Ubuntu based
if [[ ! "$ID" =~ ^(debian|ubuntu|kali|parrot)$ ]]; then
  log_warn "This script is designed for Debian/Ubuntu-based systems."
  log_warn "Your system: $ID"
  read -rp "Continue anyway? (y/n): " CONTINUE
  [[ ! "$CONTINUE" =~ ^[Yy]$ ]] && exit 1
fi

# Update package lists
log_step "Updating package lists..."
apt-get update -qq || {
  log_error "Failed to update package lists"
  exit 1
}

# Install basic dependencies
log_step "Installing required packages..."
PACKAGES=(
  "hostapd"
  "dnsmasq"
  "iptables"
  "iw"
  "wireless-tools"
  "net-tools"
  "iproute2"
)

log_info "Packages to install: ${PACKAGES[*]}"
apt-get install -y "${PACKAGES[@]}" || {
  log_error "Failed to install required packages"
  exit 1
}

log_info "✓ Basic packages installed successfully"

# Install additional dependencies for advanced features
log_step "Installing additional dependencies..."
ADDITIONAL_PACKAGES=(
  "tcpdump"
  "python3"
  "ethtool"
  "iproute2"
)

for pkg in "${ADDITIONAL_PACKAGES[@]}"; do
  if ! dpkg -l | grep -q "^ii  $pkg"; then
    apt-get install -y "$pkg" || log_warn "Could not install $pkg"
  else
    log_info "✓ $pkg already installed"
  fi
done

# Optional: aircrack-ng for advanced monitoring
read -rp "Install aircrack-ng suite for advanced monitoring? (y/n): " INSTALL_AIRCRACK
if [[ "$INSTALL_AIRCRACK" =~ ^[Yy]$ ]]; then
  apt-get install -y aircrack-ng || log_warn "Could not install aircrack-ng"
fi

# Install hostapd-wpe if requested
if [[ "$INSTALL_WPE" == true ]]; then
  log_step "Installing hostapd-wpe for password capture..."
  
  # Check if already installed
  if command -v hostapd-wpe >/dev/null 2>&1; then
    log_info "hostapd-wpe is already installed"
  else
    # Try to install from package manager first
    if apt-cache show hostapd-wpe >/dev/null 2>&1; then
      log_info "Installing hostapd-wpe from repository..."
      apt-get install -y hostapd-wpe || {
        log_warn "Failed to install hostapd-wpe from repository"
      }
    else
      log_warn "hostapd-wpe not found in repositories"
      log_info "You may need to:"
      log_info "  1. Add Kali repositories, OR"
      log_info "  2. Build from source: https://github.com/OpenSecurityResearch/hostapd-wpe"
      log_warn "Password capture mode will not be available without hostapd-wpe"
    fi
  fi
  
  # Verify installation
  if command -v hostapd-wpe >/dev/null 2>&1; then
    log_info "✓ hostapd-wpe installed successfully"
    
    # Check for required certificate files
    if [[ ! -d /etc/hostapd-wpe ]]; then
      log_warn "hostapd-wpe configuration directory not found"
      log_info "You may need to generate certificates manually"
    else
      log_info "✓ hostapd-wpe configuration directory exists"
    fi
  else
    log_warn "hostapd-wpe not installed - password capture will not work"
  fi
else
  log_info "Skipping hostapd-wpe installation (use --with-wpe to install)"
fi

# Check wireless interface
log_step "Checking for wireless interfaces..."
WIRELESS_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' || true)

if [[ -z "$WIRELESS_INTERFACES" ]]; then
  log_error "No wireless interfaces found!"
  log_error "Make sure you have a wireless adapter connected."
  log_info "Available interfaces:"
  ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - " $2}'
  exit 1
else
  log_info "Found wireless interface(s):"
  echo "$WIRELESS_INTERFACES" | while read -r iface; do
    echo "  - $iface"
  done
fi

# Check AP mode support
log_step "Checking AP mode support..."
AP_SUPPORTED=false

for iface in $WIRELESS_INTERFACES; do
  if iw phy | grep -A 10 "Supported interface modes" | grep -q "AP"; then
    AP_SUPPORTED=true
    log_info "✓ $iface supports AP mode"
  else
    log_warn "✗ $iface may not support AP mode"
  fi
done

if [[ "$AP_SUPPORTED" == false ]]; then
  log_error "No interfaces support AP mode!"
  log_error "Your wireless adapter may not be compatible."
  log_info "Check: https://wireless.wiki.kernel.org/en/users/drivers"
  exit 1
fi

# Stop conflicting services
log_step "Stopping conflicting network services..."
SERVICES_TO_STOP=("NetworkManager" "wpa_supplicant")

for service in "${SERVICES_TO_STOP[@]}"; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    log_info "Stopping $service..."
    systemctl stop "$service" 2>/dev/null || log_warn "Could not stop $service"
  fi
done

# Enable and start on boot (optional)
log_step "Service configuration..."
read -rp "Disable NetworkManager on boot? (Not recommended for desktop systems) (y/n): " DISABLE_NM
if [[ "$DISABLE_NM" =~ ^[Yy]$ ]]; then
  systemctl disable NetworkManager 2>/dev/null || true
  log_info "NetworkManager disabled on boot"
else
  log_info "NetworkManager will start on boot (you'll need to stop it manually)"
fi

# Create necessary directories
log_step "Creating directories..."
mkdir -p /var/lib/misc 2>/dev/null || true
mkdir -p /tmp 2>/dev/null || true
log_info "✓ Directories created"

# Set up iptables persistence (optional)
log_step "IPTables configuration..."
if command -v iptables-save >/dev/null 2>&1; then
  log_info "iptables is available"
  
  # Install iptables-persistent for Debian/Ubuntu
  if ! dpkg -l | grep -q iptables-persistent; then
    read -rp "Install iptables-persistent for automatic rule loading? (y/n): " INSTALL_IPTABLES_PERSISTENT
    if [[ "$INSTALL_IPTABLES_PERSISTENT" =~ ^[Yy]$ ]]; then
      echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
      echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
      apt-get install -y iptables-persistent || log_warn "Could not install iptables-persistent"
    fi
  fi
fi

# Create configuration directory
log_step "Creating configuration directory..."
mkdir -p /etc/fake_ap 2>/dev/null || true
mkdir -p /var/log/fake_ap 2>/dev/null || true

# Create default config file
if [[ ! -f /etc/fake_ap/config ]]; then
  cat > /etc/fake_ap/config <<'CONFIGEOF'
# Fake AP Default Configuration
# Edit these values to set your preferred defaults

# Network Configuration
DEFAULT_AP_IP="192.168.1.1"
DEFAULT_DHCP_START="192.168.1.2"
DEFAULT_DHCP_END="192.168.1.50"

# Default Features
DEFAULT_BANDWIDTH_LIMIT="1024"  # KB/s
DEFAULT_CHANNEL="6"

# Logging
LOG_DIRECTORY="/var/log/fake_ap"
ENABLE_DETAILED_LOGGING="true"

# Security Warnings
SHOW_SECURITY_WARNINGS="true"
CONFIGEOF
  
  log_info "✓ Created default config at /etc/fake_ap/config"
else
  log_info "Config file already exists at /etc/fake_ap/config"
fi

# Check kernel modules
log_step "Checking required kernel modules..."
REQUIRED_MODULES=("mac80211" "cfg80211")
MISSING_MODULES=()

for module in "${REQUIRED_MODULES[@]}"; do
  if lsmod | grep -q "^$module"; then
    log_info "✓ $module loaded"
  elif modprobe "$module" 2>/dev/null; then
    log_info "✓ $module loaded (was missing)"
  else
    log_warn "✗ $module not available"
    MISSING_MODULES+=("$module")
  fi
done

if [[ ${#MISSING_MODULES[@]} -gt 0 ]]; then
  log_warn "Missing modules: ${MISSING_MODULES[*]}"
  log_warn "You may need to install linux-headers or update your kernel"
fi

# Set execute permissions on fake_ap.sh
log_step "Setting permissions..."
if [[ -f "./fake_ap.sh" ]]; then
  chmod +x ./fake_ap.sh
  log_info "✓ Made fake_ap.sh executable"
else
  log_warn "fake_ap.sh not found in current directory"
  log_info "Make sure to download it and run: chmod +x fake_ap.sh"
fi

# Verify installation
log_step "Verifying installation..."
ALL_OK=true

# Check commands
REQUIRED_COMMANDS=("hostapd" "dnsmasq" "iptables" "iw" "ip")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
  if command -v "$cmd" >/dev/null 2>&1; then
    log_info "✓ $cmd: $(which $cmd)"
  else
    log_error "✗ $cmd: NOT FOUND"
    ALL_OK=false
  fi
done

# Check optional commands
if [[ "$INSTALL_WPE" == true ]]; then
  if command -v hostapd-wpe >/dev/null 2>&1; then
    log_info "✓ hostapd-wpe: $(which hostapd-wpe)"
  else
    log_warn "✗ hostapd-wpe: NOT FOUND (password capture unavailable)"
  fi
fi

# System info
log_step "System information..."
echo -e "${BLUE}Kernel:${NC} $(uname -r)"
echo -e "${BLUE}Wireless interfaces:${NC}"
iw dev 2>/dev/null | grep -E 'Interface|addr' | sed 's/^/  /'

# Final summary
echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
if [[ "$ALL_OK" == true ]]; then
  echo -e "${GREEN}║          ✓ Setup completed successfully!             ║${NC}"
else
  echo -e "${YELLOW}║        ⚠ Setup completed with warnings               ║${NC}"
fi
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo

log_info "Next steps:"
echo "  1. Run: sudo ./fake_ap.sh --help"
echo "  2. Basic AP: sudo ./fake_ap.sh \"MyFakeAP\" 6 eth0"
if [[ "$INSTALL_WPE" == true ]] && command -v hostapd-wpe >/dev/null 2>&1; then
  echo "  3. With password capture: sudo ./fake_ap.sh \"MyFakeAP\" 6 eth0 --capture-auth"
fi
echo "  4. Advanced features: sudo ./fake_ap.sh \"MyFakeAP\" 6 eth0 --monitor --captive-portal"
echo "  5. Check adapters: sudo ./fake_ap.sh list-adapters"
echo "  6. Edit config: nano /etc/fake_ap/config"
echo

log_warn "IMPORTANT REMINDERS:"
echo "  • Only use this on networks you own or have permission to test"
echo "  • Unauthorized access point creation may be illegal"
echo "  • Password capture is for authorized security testing only"
echo "  • Review your local laws and regulations"
echo

if [[ "$ALL_OK" != true ]]; then
  log_warn "Some components failed to install. Check the errors above."
  exit 1
fi

log_info "Setup complete! You can now run fake_ap.sh"
exit 0