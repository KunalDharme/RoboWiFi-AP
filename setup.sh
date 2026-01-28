#!/usr/bin/env bash
#
# ╔══════════════════════════════════════════════════════════════════════╗
# ║                    RoboWiFi-AP Setup Script                          ║
# ║           Installs Dependencies & Configures System                  ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# Description: Setup script for RoboWiFi-AP toolkit
# Installs dependencies and prepares system for running fake access point
#
# Usage:
#   sudo ./setup.sh [OPTIONS]
#
# Options:
#   --with-wpe    Install hostapd-wpe for password capture (optional)
#   --help, -h    Show help message
#
# Version: 2.0

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════
# COLOR DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# ═══════════════════════════════════════════════════════════════════════
# GLOBAL VARIABLES
# ═══════════════════════════════════════════════════════════════════════
INSTALL_WPE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/robowifi_setup_$(date +%Y%m%d_%H%M%S).log"
ERROR_COUNT=0
WARNING_COUNT=0

# ═══════════════════════════════════════════════════════════════════════
# LOGGING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════
log_info() {
    echo -e "${GREEN}[✔]${NC} $*" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"
    ((WARNING_COUNT++))
}

log_error() {
    echo -e "${RED}[✖]${NC} $*" | tee -a "$LOG_FILE"
    ((ERROR_COUNT++))
}

log_step() {
    echo -e "\n${CYAN}${BOLD}═══>${NC} ${WHITE}$*${NC}" | tee -a "$LOG_FILE"
}

log_substep() {
    echo -e "  ${BLUE}→${NC} $*" | tee -a "$LOG_FILE"
}

# ═══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat <<'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗  ██████╗ ██████╗  ██████╗ ██╗    ██╗██╗███████╗██╗        ║
║   ██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗██║    ██║██║██╔════╝██║        ║
║   ██████╔╝██║   ██║██████╔╝██║   ██║██║ █╗ ██║██║█████╗  ██║        ║
║   ██╔══██╗██║   ██║██╔══██╗██║   ██║██║███╗██║██║██╔══╝  ██║        ║
║   ██║  ██║╚██████╔╝██████╔╝╚██████╔╝╚███╔███╔╝██║██║     ██║        ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝        ║
║                                                                      ║
║                    SETUP & INSTALLATION WIZARD                      ║
║                        Version 2.0 - 2025                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

confirm_action() {
    local prompt="$1"
    local default="${2:-n}"
    local response
    
    if [[ "$default" == "y" ]]; then
        echo -ne "${YELLOW}$prompt [Y/n]:${NC} "
    else
        echo -ne "${YELLOW}$prompt [y/N]:${NC} "
    fi
    
    read -r response
    response=${response:-$default}
    
    [[ "$response" =~ ^[Yy]$ ]]
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# ═══════════════════════════════════════════════════════════════════════
# SYSTEM CHECK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════
check_root() {
    log_step "Checking permissions"
    
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo -e "${RED}${BOLD}Please run: sudo $0${NC}"
        exit 1
    fi
    
    log_info "Running with root privileges"
}

detect_os() {
    log_step "Detecting operating system"
    
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS - /etc/os-release not found"
        exit 1
    fi
    
    source /etc/os-release
    
    log_info "OS Name: $NAME"
    log_info "Version: $VERSION_ID"
    log_info "ID: $ID"
    
    if [[ ! "$ID" =~ ^(debian|ubuntu|kali|parrot|mint)$ ]]; then
        log_warn "This script is optimized for Debian/Ubuntu-based systems"
        log_warn "Your system: $ID"
        
        if ! confirm_action "Continue anyway?"; then
            log_error "Installation cancelled by user"
            exit 1
        fi
    fi
}

check_internet() {
    log_step "Checking internet connectivity"
    
    if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        log_info "Internet connection: Active"
    else
        log_warn "No internet connection detected"
        log_warn "Some packages may fail to install"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# PACKAGE INSTALLATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════
update_package_lists() {
    log_step "Updating package lists"
    
    if apt-get update -qq 2>&1 | tee -a "$LOG_FILE" >/dev/null; then
        log_info "Package lists updated successfully"
    else
        log_error "Failed to update package lists"
        exit 1
    fi
}

install_package() {
    local package="$1"
    local display_name="${2:-$package}"
    
    if dpkg -l | grep -q "^ii  $package"; then
        log_info "$display_name: Already installed"
        return 0
    fi
    
    log_substep "Installing $display_name..."
    
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$package" >> "$LOG_FILE" 2>&1; then
        log_info "$display_name: Installed successfully"
        return 0
    else
        log_error "$display_name: Installation failed"
        return 1
    fi
}

install_core_packages() {
    log_step "Installing core packages"
    
    local packages=(
        "hostapd:Hostapd (AP daemon)"
        "dnsmasq:DNSMasq (DHCP/DNS)"
        "iptables:IPTables (firewall)"
        "iw:Wireless tools (iw)"
        "wireless-tools:Wireless tools"
        "net-tools:Network tools"
        "iproute2:IP Route tools"
    )
    
    for pkg_info in "${packages[@]}"; do
        IFS=':' read -r pkg display <<< "$pkg_info"
        install_package "$pkg" "$display"
    done
}

install_optional_packages() {
    log_step "Installing optional tools"
    
    local packages=(
        "tcpdump:TCPDump (packet capture)"
        "python3:Python 3"
        "python3-pip:Python pip"
        "ethtool:Ethtool (adapter info)"
    )
    
    for pkg_info in "${packages[@]}"; do
        IFS=':' read -r pkg display <<< "$pkg_info"
        install_package "$pkg" "$display" || log_warn "Optional: $display skipped"
    done
    
    # Optional: aircrack-ng
    if confirm_action "Install aircrack-ng suite for advanced monitoring?" "n"; then
        install_package "aircrack-ng" "Aircrack-ng suite" || log_warn "Aircrack-ng installation failed"
    fi
}

install_hostapd_wpe() {
    log_step "Installing hostapd-wpe (password capture)"
    
    if check_command hostapd-wpe; then
        log_info "hostapd-wpe: Already installed"
        return 0
    fi
    
    if apt-cache show hostapd-wpe >/dev/null 2>&1; then
        log_substep "Installing from repository..."
        if install_package "hostapd-wpe" "Hostapd-WPE"; then
            log_info "hostapd-wpe installed successfully"
        else
            log_error "Failed to install hostapd-wpe"
            return 1
        fi
    else
        log_warn "hostapd-wpe not found in repositories"
        echo -e "\n${YELLOW}To install hostapd-wpe manually:${NC}"
        echo -e "  ${WHITE}1.${NC} Add Kali repositories, OR"
        echo -e "  ${WHITE}2.${NC} Build from source: ${CYAN}https://github.com/OpenSecurityResearch/hostapd-wpe${NC}"
        log_warn "Password capture mode will not be available without hostapd-wpe"
        return 1
    fi
    
    # Verify configuration directory
    if [[ -d /etc/hostapd-wpe ]]; then
        log_info "Configuration directory found"
    else
        log_warn "Configuration directory missing - may need manual setup"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# WIRELESS INTERFACE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════
check_wireless_interfaces() {
    log_step "Checking wireless interfaces"
    
    local interfaces
    interfaces=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' || true)
    
    if [[ -z "$interfaces" ]]; then
        log_error "No wireless interfaces found"
        echo -e "\n${YELLOW}Available network interfaces:${NC}"
        ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  • " $2}'
        log_error "Make sure you have a wireless adapter connected"
        exit 1
    fi
    
    log_info "Found wireless interface(s):"
    while IFS= read -r iface; do
        echo -e "  ${GREEN}•${NC} $iface"
    done <<< "$interfaces"
}

check_ap_mode_support() {
    log_step "Verifying AP mode support"
    
    if iw phy 2>/dev/null | grep -A 10 "Supported interface modes" | grep -q "AP"; then
        log_info "AP mode is supported"
    else
        log_error "No interfaces support AP mode"
        echo -e "\n${YELLOW}Your wireless adapter may not be compatible${NC}"
        echo -e "Check: ${CYAN}https://wireless.wiki.kernel.org/en/users/drivers${NC}"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# SYSTEM CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════
configure_services() {
    log_step "Configuring system services"
    
    local services=("NetworkManager" "wpa_supplicant")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_substep "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || log_warn "Could not stop $service"
        fi
    done
    
    if confirm_action "Disable NetworkManager on boot? (Not recommended for desktops)" "n"; then
        systemctl disable NetworkManager 2>/dev/null || true
        log_info "NetworkManager disabled on boot"
    else
        log_info "NetworkManager will start on boot (stop manually before using tools)"
    fi
}

setup_iptables() {
    log_step "Configuring IPTables"
    
    if check_command iptables-save; then
        log_info "IPTables is available"
        
        if ! dpkg -l | grep -q iptables-persistent; then
            if confirm_action "Install iptables-persistent for automatic rules?" "n"; then
                echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
                echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
                install_package "iptables-persistent" "IPTables Persistent"
            fi
        fi
    else
        log_error "IPTables not found"
    fi
}

create_directories() {
    log_step "Creating directories"
    
    local dirs=(
        "/etc/robowifi"
        "/var/log/robowifi"
        "/var/lib/misc"
    )
    
    for dir in "${dirs[@]}"; do
        if mkdir -p "$dir" 2>/dev/null; then
            chmod 700 "$dir" 2>/dev/null || true
            log_substep "Created: $dir"
        else
            log_warn "Could not create: $dir"
        fi
    done
}

create_config_file() {
    log_step "Creating configuration file"
    
    local config_file="/etc/robowifi/config"
    
    if [[ -f "$config_file" ]]; then
        log_info "Configuration file already exists"
        return 0
    fi
    
    cat > "$config_file" <<'CONFIGEOF'
# ═══════════════════════════════════════════════════════════════════════
# RoboWiFi-AP Configuration
# ═══════════════════════════════════════════════════════════════════════

# Network Configuration
DEFAULT_AP_IP="192.168.1.1"
DEFAULT_DHCP_START="192.168.1.2"
DEFAULT_DHCP_END="192.168.1.50"

# Default Settings
DEFAULT_CHANNEL="6"
DEFAULT_BANDWIDTH_LIMIT="1024"  # KB/s

# Logging
LOG_DIRECTORY="/var/log/robowifi"
ENABLE_DETAILED_LOGGING="true"

# Security
SHOW_SECURITY_WARNINGS="true"
REQUIRE_AUTHORIZATION="true"
CONFIGEOF
    
    chmod 600 "$config_file"
    log_info "Configuration created: $config_file"
}

check_kernel_modules() {
    log_step "Checking kernel modules"
    
    local modules=("mac80211" "cfg80211")
    local missing=()
    
    for module in "${modules[@]}"; do
        if lsmod | grep -q "^$module"; then
            log_info "$module: Loaded"
        elif modprobe "$module" 2>/dev/null; then
            log_info "$module: Loaded (was missing)"
        else
            log_warn "$module: Not available"
            missing+=("$module")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Missing modules: ${missing[*]}"
        log_warn "May need linux-headers or kernel update"
    fi
}

set_permissions() {
    log_step "Setting file permissions"
    
    local scripts=("fake_ap.sh" "advanced_fake_ap.sh" "fake_ap_detector.sh")
    local found=0
    
    # Check main directory
    for script in "${scripts[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            chmod +x "$SCRIPT_DIR/$script"
            log_info "Made $script executable"
            ((found++))
        elif [[ -f "$SCRIPT_DIR/scripts/$script" ]]; then
            chmod +x "$SCRIPT_DIR/scripts/$script"
            log_info "Made scripts/$script executable"
            ((found++))
        fi
    done
    
    # Check main.py
    if [[ -f "$SCRIPT_DIR/main.py" ]]; then
        chmod +x "$SCRIPT_DIR/main.py"
        log_info "Made main.py executable"
    fi
    
    if [[ $found -eq 0 ]]; then
        log_warn "No scripts found to set permissions"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# VERIFICATION
# ═══════════════════════════════════════════════════════════════════════
verify_installation() {
    log_step "Verifying installation"
    
    local required_commands=("hostapd" "dnsmasq" "iptables" "iw" "ip")
    local all_ok=true
    
    for cmd in "${required_commands[@]}"; do
        if check_command "$cmd"; then
            log_info "$cmd: $(command -v "$cmd")"
        else
            log_error "$cmd: NOT FOUND"
            all_ok=false
        fi
    done
    
    # Check optional
    if [[ "$INSTALL_WPE" == true ]]; then
        if check_command hostapd-wpe; then
            log_info "hostapd-wpe: $(command -v hostapd-wpe)"
        else
            log_warn "hostapd-wpe: NOT FOUND"
        fi
    fi
    
    echo "$all_ok"
}

print_system_info() {
    log_step "System information"
    
    echo -e "${CYAN}Kernel:${NC} $(uname -r)"
    echo -e "${CYAN}Architecture:${NC} $(uname -m)"
    echo -e "${CYAN}Wireless interfaces:${NC}"
    iw dev 2>/dev/null | grep -E 'Interface|addr' | sed 's/^/  /' || echo "  None"
}

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
print_summary() {
    local all_ok="$1"
    
    echo
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    
    if [[ "$all_ok" == "true" && $ERROR_COUNT -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}✓ SETUP COMPLETED SUCCESSFULLY!${NC}"
    else
        echo -e "${YELLOW}${BOLD}⚠ SETUP COMPLETED WITH WARNINGS${NC}"
    fi
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${CYAN}${BOLD}Next Steps:${NC}"
    echo -e "  ${WHITE}1.${NC} Run main interface:  ${GREEN}sudo python3 main.py${NC}"
    echo -e "  ${WHITE}2.${NC} Direct script usage: ${GREEN}sudo ./scripts/fake_ap.sh --help${NC}"
    echo -e "  ${WHITE}3.${NC} List adapters:       ${GREEN}sudo ./scripts/fake_ap.sh list-adapters${NC}"
    echo -e "  ${WHITE}4.${NC} Basic AP example:    ${GREEN}sudo ./scripts/fake_ap.sh \"TestAP\" 6 eth0${NC}"
    
    if [[ "$INSTALL_WPE" == true ]] && check_command hostapd-wpe; then
        echo -e "  ${WHITE}5.${NC} Password capture:    ${GREEN}sudo ./scripts/fake_ap.sh \"TestAP\" 6 eth0 --capture-auth${NC}"
    fi
    
    echo -e "\n${YELLOW}${BOLD}⚠ IMPORTANT:${NC}"
    echo -e "  ${RED}•${NC} Only use on networks you own or have authorization to test"
    echo -e "  ${RED}•${NC} Unauthorized use may be illegal in your jurisdiction"
    echo -e "  ${RED}•${NC} Password capture requires explicit authorization"
    echo -e "  ${RED}•${NC} Always comply with applicable laws and regulations"
    
    echo -e "\n${CYAN}Installation Summary:${NC}"
    echo -e "  ${WHITE}Errors:${NC}   ${RED}$ERROR_COUNT${NC}"
    echo -e "  ${WHITE}Warnings:${NC} ${YELLOW}$WARNING_COUNT${NC}"
    echo -e "  ${WHITE}Log:${NC}      ${CYAN}$LOG_FILE${NC}"
    
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
}

# ═══════════════════════════════════════════════════════════════════════
# HELP
# ═══════════════════════════════════════════════════════════════════════
show_help() {
    cat <<EOF
${GREEN}${BOLD}RoboWiFi-AP Setup Script${NC}

Installs and configures all dependencies for RoboWiFi-AP toolkit

${CYAN}${BOLD}USAGE:${NC}
  sudo $0 [OPTIONS]

${CYAN}${BOLD}OPTIONS:${NC}
  ${WHITE}--with-wpe${NC}    Install hostapd-wpe for password capture
  ${WHITE}--help, -h${NC}    Show this help message

${CYAN}${BOLD}WHAT THIS DOES:${NC}
  ${GREEN}1.${NC} Checks system requirements
  ${GREEN}2.${NC} Installs packages (hostapd, dnsmasq, iptables, etc.)
  ${GREEN}3.${NC} Optionally installs hostapd-wpe
  ${GREEN}4.${NC} Verifies wireless adapter capabilities
  ${GREEN}5.${NC} Configures system settings
  ${GREEN}6.${NC} Creates directories and configuration

${CYAN}${BOLD}REQUIREMENTS:${NC}
  ${WHITE}•${NC} Debian/Ubuntu-based Linux
  ${WHITE}•${NC} Root/sudo access
  ${WHITE}•${NC} Wireless adapter with AP mode support
  ${WHITE}•${NC} Internet connection (for package installation)

${YELLOW}${BOLD}LEGAL:${NC}
Only use on networks you own or have written authorization to test.

${CYAN}${BOLD}EXAMPLES:${NC}
  ${WHITE}# Basic setup${NC}
  sudo $0

  ${WHITE}# Setup with password capture support${NC}
  sudo $0 --with-wpe
EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════
main() {
    # Parse arguments
    for arg in "$@"; do
        case "$arg" in
            --with-wpe)
                INSTALL_WPE=true
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $arg"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Start
    print_banner
    echo -e "${WHITE}Installation log:${NC} ${CYAN}$LOG_FILE${NC}\n"
    
    # Pre-checks
    check_root
    detect_os
    check_internet
    
    # Install packages
    update_package_lists
    install_core_packages
    install_optional_packages
    
    # Optional hostapd-wpe
    if [[ "$INSTALL_WPE" == true ]]; then
        install_hostapd_wpe
    else
        log_info "Skipping hostapd-wpe (use --with-wpe to install)"
    fi
    
    # System configuration
    check_wireless_interfaces
    check_ap_mode_support
    configure_services
    setup_iptables
    create_directories
    create_config_file
    check_kernel_modules
    set_permissions
    
    # Verification
    local all_ok
    all_ok=$(verify_installation)
    print_system_info
    
    # Summary
    print_summary "$all_ok"
    
    # Exit
    if [[ "$all_ok" == "true" && $ERROR_COUNT -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run
main "$@"
