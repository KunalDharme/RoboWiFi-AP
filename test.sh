#!/usr/bin/env bash
# test.sh - Test and validate fake AP setup
# Checks system compatibility and runs diagnostics
#
# Usage:
#   sudo ./test.sh [OPTIONS]
#     --full        Run comprehensive tests
#     --quick       Quick compatibility check
#     --fix         Attempt to fix common issues
#     --adapter IF  Test specific adapter

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[✓]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[!]${NC} $*"
}

log_error() {
  echo -e "${RED}[✗]${NC} $*"
}

log_test() {
  echo -e "${CYAN}[TEST]${NC} $*"
}

# Default options
TEST_MODE="quick"
FIX_ISSUES=false
SPECIFIC_ADAPTER=""

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --full)
      TEST_MODE="full"
      ;;
    --quick)
      TEST_MODE="quick"
      ;;
    --fix)
      FIX_ISSUES=true
      ;;
    --adapter)
      shift
      SPECIFIC_ADAPTER="${1:-}"
      ;;
    --help|-h)
      cat <<EOF
${GREEN}Fake AP Testing & Validation Script${NC}

Usage:
  sudo $0 [OPTIONS]

Options:
  --quick       Quick compatibility check (default)
  --full        Comprehensive system testing
  --fix         Attempt to fix common issues
  --adapter IF  Test specific wireless adapter
  --help, -h    Show this help message

Tests performed:
  - System requirements check
  - Wireless adapter compatibility
  - Driver support verification
  - AP mode capability testing
  - Network configuration validation
  - Permission and security checks
  - Service availability

Examples:
  sudo $0 --quick
  sudo $0 --full --fix
  sudo $0 --adapter wlan0
EOF
      exit 0
      ;;
  esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root: sudo $0"
  exit 1
fi

echo -e "${GREEN}"
cat <<'EOF'
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║       Fake AP Testing & Validation Suite             ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

# Test function
run_test() {
  local test_name="$1"
  local test_command="$2"
  local required="${3:-true}"
  
  log_test "$test_name"
  
  if eval "$test_command" >/dev/null 2>&1; then
    log_info "$test_name: PASSED"
    ((TESTS_PASSED++))
    return 0
  else
    if [[ "$required" == "true" ]]; then
      log_error "$test_name: FAILED"
      ((TESTS_FAILED++))
    else
      log_warn "$test_name: WARNING"
      ((TESTS_WARNED++))
    fi
    return 1
  fi
}

echo -e "\n${BLUE}=== System Requirements Check ===${NC}\n"

# Check OS
run_test "Operating System Detection" "test -f /etc/os-release"
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  echo "  OS: $NAME $VERSION_ID"
fi

# Check architecture
ARCH=$(uname -m)
echo "  Architecture: $ARCH"

# Check kernel version
KERNEL=$(uname -r)
echo "  Kernel: $KERNEL"
run_test "Kernel version check" "test ! -z '$KERNEL'"

echo -e "\n${BLUE}=== Required Commands Check ===${NC}\n"

# Required commands
REQUIRED_CMDS=("hostapd" "dnsmasq" "iptables" "iw" "ip" "sysctl")
for cmd in "${REQUIRED_CMDS[@]}"; do
  if run_test "Command: $cmd" "command -v $cmd"; then
    echo "  Location: $(which $cmd)"
    if [[ "$cmd" == "hostapd" ]]; then
      VERSION=$(hostapd -v 2>&1 | head -1 || echo "Unknown")
      echo "  Version: $VERSION"
    fi
  fi
done

# Optional commands
echo -e "\n${BLUE}=== Optional Tools Check ===${NC}\n"
OPTIONAL_CMDS=("hostapd-wpe" "tcpdump" "python3" "ethtool" "airmon-ng")
for cmd in "${OPTIONAL_CMDS[@]}"; do
  run_test "Optional: $cmd" "command -v $cmd" "false"
done

echo -e "\n${BLUE}=== Wireless Adapter Check ===${NC}\n"

# Find wireless interfaces
WIRELESS_ADAPTERS=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' || true)

if [[ -z "$WIRELESS_ADAPTERS" ]]; then
  log_error "No wireless adapters found!"
  echo "  Available interfaces:"
  ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "    - " $2}'
  ((TESTS_FAILED++))
else
  log_info "Found wireless adapter(s):"
  for adapter in $WIRELESS_ADAPTERS; do
    echo "    - $adapter"
  done
  
  # Test each adapter or specific one
  TEST_ADAPTERS="$WIRELESS_ADAPTERS"
  [[ -n "$SPECIFIC_ADAPTER" ]] && TEST_ADAPTERS="$SPECIFIC_ADAPTER"
  
  for adapter in $TEST_ADAPTERS; do
    echo -e "\n  ${CYAN}Testing adapter: $adapter${NC}"
    
    # Check if interface exists
    if ! ip link show "$adapter" >/dev/null 2>&1; then
      log_error "$adapter does not exist"
      ((TESTS_FAILED++))
      continue
    fi
    
    # Get PHY
    PHY=$(iw "$adapter" info 2>/dev/null | grep wiphy | awk '{print $2}' || echo "")
    if [[ -n "$PHY" ]]; then
      echo "    PHY: phy$PHY"
      
      # Check AP mode support
      if iw phy "phy$PHY" info 2>/dev/null | grep -q "* AP$"; then
        log_info "AP mode: SUPPORTED"
        ((TESTS_PASSED++))
      else
        log_error "AP mode: NOT SUPPORTED"
        ((TESTS_FAILED++))
      fi
      
      # Check monitor mode support
      if iw phy "phy$PHY" info 2>/dev/null | grep -q "* monitor$"; then
        log_info "Monitor mode: SUPPORTED"
      else
        log_warn "Monitor mode: NOT SUPPORTED"
        ((TESTS_WARNED++))
      fi
      
      # Get driver info
      if command -v ethtool >/dev/null 2>&1; then
        DRIVER=$(ethtool -i "$adapter" 2>/dev/null | grep driver | awk '{print $2}' || echo "Unknown")
        echo "    Driver: $DRIVER"
        
        # Check for known problematic drivers
        case "$DRIVER" in
          rtl*|r8*|8192*)
            log_warn "Driver $DRIVER may have limited AP mode support"
            ((TESTS_WARNED++))
            ;;
          ath*|iwl*|mt76*)
            log_info "Driver $DRIVER generally has good AP support"
            ;;
        esac
      fi
      
      # Check channels
      CHANNELS=$(iw phy "phy$PHY" channels 2>/dev/null | grep -c "MHz" || echo "0")
      echo "    Available channels: $CHANNELS"
      
      # Check TX power
      TX_POWER=$(iw "$adapter" info 2>/dev/null | grep txpower | awk '{print $2 " " $3}' || echo "Unknown")
      echo "    TX Power: $TX_POWER"
      
    else
      log_error "Could not get PHY information for $adapter"
      ((TESTS_FAILED++))
    fi
  done
fi

echo -e "\n${BLUE}=== Kernel Modules Check ===${NC}\n"

# Required kernel modules
REQUIRED_MODULES=("mac80211" "cfg80211")
for module in "${REQUIRED_MODULES[@]}"; do
  if lsmod | grep -q "^$module"; then
    log_info "Module $module: LOADED"
    ((TESTS_PASSED++))
  else
    log_warn "Module $module: NOT LOADED"
    if [[ "$FIX_ISSUES" == true ]]; then
      log_info "Attempting to load $module..."
      if modprobe "$module" 2>/dev/null; then
        log_info "Successfully loaded $module"
      else
        log_error "Failed to load $module"
        ((TESTS_FAILED++))
      fi
    else
      ((TESTS_WARNED++))
    fi
  fi
done

echo -e "\n${BLUE}=== Network Configuration Check ===${NC}\n"

# Check IP forwarding capability
if sysctl net.ipv4.ip_forward >/dev/null 2>&1; then
  FORWARD_STATUS=$(sysctl -n net.ipv4.ip_forward)
  echo "  IP Forwarding: $([[ "$FORWARD_STATUS" == "1" ]] && echo "ENABLED" || echo "DISABLED")"
  log_info "IP forwarding support: AVAILABLE"
  ((TESTS_PASSED++))
else
  log_error "Cannot check IP forwarding"
  ((TESTS_FAILED++))
fi

# Check iptables
if run_test "iptables functionality" "iptables -L -n >/dev/null 2>&1"; then
  IPTABLES_RULES=$(iptables -L -n 2>/dev/null | wc -l)
  echo "  Current iptables rules: $IPTABLES_RULES"
fi

# Check for conflicting services
echo -e "\n${BLUE}=== Service Conflicts Check ===${NC}\n"

CONFLICTING_SERVICES=("NetworkManager" "wpa_supplicant")
for service in "${CONFLICTING_SERVICES[@]}"; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then
    log_warn "$service is running (may need to be stopped)"
    ((TESTS_WARNED++))
    if [[ "$FIX_ISSUES" == true ]]; then
      read -rp "Stop $service? (y/n): " STOP_SERVICE
      if [[ "$STOP_SERVICE" =~ ^[Yy]$ ]]; then
        systemctl stop "$service"
        log_info "$service stopped"
      fi
    fi
  else
    log_info "$service is not running"
  fi
done

if [[ "$TEST_MODE" == "full" ]]; then
  echo -e "\n${BLUE}=== Full System Tests ===${NC}\n"
  
  # Test creating virtual interface
  if [[ -n "$WIRELESS_ADAPTERS" ]]; then
    TEST_ADAPTER=$(echo "$WIRELESS_ADAPTERS" | head -1)
    log_test "Virtual interface creation test"
    
    if ip link add test_virt type dummy 2>/dev/null; then
      log_info "Virtual interface creation: SUCCESS"
      ip link delete test_virt 2>/dev/null
      ((TESTS_PASSED++))
    else
      log_warn "Virtual interface creation: LIMITED"
      ((TESTS_WARNED++))
    fi
  fi
  
  # Test dnsmasq config
  log_test "dnsmasq configuration test"
  TEST_CONF="/tmp/test_dnsmasq.conf"
  cat > "$TEST_CONF" <<EOF
interface=test
bind-interfaces
dhcp-range=192.168.1.2,192.168.1.50,12h
EOF
  
  if dnsmasq --test --conf-file="$TEST_CONF" 2>/dev/null; then
    log_info "dnsmasq configuration: VALID"
    ((TESTS_PASSED++))
  else
    log_error "dnsmasq configuration: INVALID"
    ((TESTS_FAILED++))
  fi
  rm -f "$TEST_CONF"
  
  # Test hostapd config
  log_test "hostapd configuration test"
  TEST_HOSTAPD="/tmp/test_hostapd.conf"
  cat > "$TEST_HOSTAPD" <<EOF
interface=test
ssid=test
channel=6
hw_mode=g
EOF
  
  if hostapd -d "$TEST_HOSTAPD" 2>&1 | grep -q "Configuration file: $TEST_HOSTAPD"; then
    log_info "hostapd configuration: VALID"
    ((TESTS_PASSED++))
  else
    log_warn "hostapd configuration: CHECK MANUAL"
    ((TESTS_WARNED++))
  fi
  rm -f "$TEST_HOSTAPD"
fi

# Check for common issues
echo -e "\n${BLUE}=== Common Issues Check ===${NC}\n"

# Check if running in VM
if grep -q "hypervisor" /proc/cpuinfo 2>/dev/null; then
  log_warn "Running in virtual machine - wireless features may be limited"
  ((TESTS_WARNED++))
fi

# Check USB wireless adapters
if lsusb 2>/dev/null | grep -i "wireless\|802\.11\|wifi" >/dev/null; then
  log_info "USB wireless adapter(s) detected"
  echo "  Devices:"
  lsusb | grep -i "wireless\|802\.11\|wifi" | sed 's/^/    /'
fi

# Check for firmware issues
if dmesg | grep -i "firmware.*fail" >/dev/null 2>&1; then
  log_warn "Firmware loading issues detected in dmesg"
  ((TESTS_WARNED++))
fi

# Final summary
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  TEST SUMMARY                         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo
echo -e "  ${GREEN}Tests Passed:${NC}  $TESTS_PASSED"
echo -e "  ${YELLOW}Warnings:${NC}      $TESTS_WARNED"
echo -e "  ${RED}Tests Failed:${NC}  $TESTS_FAILED"
echo

# Overall result
if [[ $TESTS_FAILED -eq 0 ]]; then
  if [[ $TESTS_WARNED -eq 0 ]]; then
    echo -e "${GREEN}✓ All tests passed! Your system is ready to run fake_ap.sh${NC}"
    exit 0
  else
    echo -e "${YELLOW}⚠ Tests passed with warnings. Review warnings above.${NC}"
    echo -e "  Your system should work but may have limitations."
    exit 0
  fi
else
  echo -e "${RED}✗ Some critical tests failed.${NC}"
  echo -e "  Please fix the issues above before running fake_ap.sh"
  echo
  echo "Common fixes:"
  echo "  - Install missing packages: sudo ./setup.sh"
  echo "  - Check adapter compatibility: sudo ./fake_ap.sh list-adapters"
  echo "  - Run with --fix flag: sudo $0 --fix"
  echo "  - Update drivers or kernel"
  exit 1
fi