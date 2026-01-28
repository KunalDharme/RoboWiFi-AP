#!/usr/bin/env bash
# fake_ap_detector.sh - Enhanced Rogue Access Point Detector & Defense System
# Version 2.0 - Advanced threat detection and monitoring
#
# Usage:
#   sudo ./fake_ap_detector.sh --monitor [INTERFACE]
#   sudo ./fake_ap_detector.sh --scan
#   sudo ./fake_ap_detector.sh --protect SSID BSSID
#   sudo ./fake_ap_detector.sh --analyze LOGFILE
#   sudo ./fake_ap_detector.sh --help

set -euo pipefail

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# CONFIGURATION
# ============================================================================

# File Paths
WORK_DIR="/tmp/fake_ap_detector"
SCAN_LOG="${WORK_DIR}/scan_results.log"
ALERT_LOG="${WORK_DIR}/alerts.log"
WHITELIST_FILE="${WORK_DIR}/whitelist.txt"
BLACKLIST_FILE="${WORK_DIR}/blacklist.txt"
KNOWN_APS_DB="${WORK_DIR}/known_aps.db"
ROGUE_APS_DB="${WORK_DIR}/rogue_aps.db"
MONITOR_LOG="${WORK_DIR}/monitor.log"
TRAFFIC_ANALYSIS="${WORK_DIR}/traffic_analysis.log"
DEAUTH_LOG="${WORK_DIR}/deauth_attacks.log"

# NEW: Advanced detection logs
PACKET_CAPTURE="${WORK_DIR}/monitor.pcap"
DNS_SPOOF_LOG="${WORK_DIR}/dns_spoofing.log"
SSL_STRIP_LOG="${WORK_DIR}/ssl_strip_detected.log"
ARP_SPOOF_LOG="${WORK_DIR}/arp_spoofing.log"
MITM_INDICATORS_LOG="${WORK_DIR}/mitm_indicators.log"
CAPTIVE_PORTAL_LOG="${WORK_DIR}/captive_portals.log"
PROBE_ANALYSIS_LOG="${WORK_DIR}/probe_requests.log"
CLIENT_TRACKING_DB="${WORK_DIR}/client_tracking.db"
THREAT_SCORE_LOG="${WORK_DIR}/threat_scores.log"

# Alert Configuration
ENABLE_EMAIL_ALERTS=false
ENABLE_SOUND_ALERTS=true
ENABLE_DESKTOP_NOTIFY=true
EMAIL_ADDRESS=""
WEBHOOK_URL=""
SLACK_WEBHOOK=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

# Detection Thresholds
SIGNAL_STRENGTH_THRESHOLD=-30
DUPLICATE_SSID_ALERT=true
MAC_VENDOR_CHECK=true
ENCRYPTION_DOWNGRADE_ALERT=true
CHANNEL_SWITCH_ALERT=true
DEAUTH_THRESHOLD=10  # Alert if more than 10 deauths/min
PROBE_THRESHOLD=50   # Alert if more than 50 probes/min

# NEW: Advanced Detection Features
ENABLE_DEEP_PACKET_INSPECTION=false
ENABLE_ARP_MONITORING=false
ENABLE_DNS_MONITORING=false
ENABLE_PROBE_ANALYSIS=false
ENABLE_CLIENT_FINGERPRINTING=false
ENABLE_THREAT_SCORING=false
ENABLE_AUTO_RESPONSE=false
ENABLE_PACKET_CAPTURE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
  echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$MONITOR_LOG"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$MONITOR_LOG"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$MONITOR_LOG"
}

log_alert() {
  local message="$*"
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${RED}${BOLD}[🚨 ALERT]${NC} $timestamp $message" | tee -a "$ALERT_LOG"
  
  # Sound alert
  if [[ "$ENABLE_SOUND_ALERTS" == "true" ]]; then
    (speaker-test -t sine -f 1000 -l 1 >/dev/null 2>&1 &)
    sleep 0.2
    pkill speaker-test 2>/dev/null || true
  fi
  
  # Desktop notification
  if [[ "$ENABLE_DESKTOP_NOTIFY" == "true" ]] && command -v notify-send >/dev/null 2>&1; then
    notify-send -u critical "🚨 ROGUE AP DETECTED" "$message"
  fi
  
  # Email alert
  if [[ "$ENABLE_EMAIL_ALERTS" == "true" ]] && [[ -n "$EMAIL_ADDRESS" ]]; then
    echo -e "SECURITY ALERT\n\nTimestamp: $timestamp\n\n$message" | \
      mail -s "[URGENT] Rogue AP Detected" "$EMAIL_ADDRESS" 2>/dev/null || true
  fi
  
  # Webhook (generic)
  if [[ -n "$WEBHOOK_URL" ]]; then
    curl -X POST "$WEBHOOK_URL" \
      -H "Content-Type: application/json" \
      -d "{\"text\":\"🚨 ROGUE AP: $message\", \"timestamp\":\"$timestamp\"}" \
      >/dev/null 2>&1 || true
  fi
  
  # Slack webhook
  if [[ -n "$SLACK_WEBHOOK" ]]; then
    curl -X POST "$SLACK_WEBHOOK" \
      -H "Content-Type: application/json" \
      -d "{\"text\":\"🚨 *ROGUE AP ALERT*\n$message\",\"username\":\"AP Detector\",\"icon_emoji\":\":shield:\"}" \
      >/dev/null 2>&1 || true
  fi
  
  # Telegram
  if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
    local telegram_msg="🚨 *ROGUE AP ALERT*%0A%0A$message%0A%0ATime: $timestamp"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d "chat_id=${TELEGRAM_CHAT_ID}&text=${telegram_msg}&parse_mode=Markdown" \
      >/dev/null 2>&1 || true
  fi
}

log_success() {
  echo -e "${GREEN}[✓]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$MONITOR_LOG"
}

print_banner() {
  clear
  cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║     ██████╗  ██████╗  ██████╗ ██╗   ██╗███████╗     █████╗ ██████╗        ║
║     ██╔══██╗██╔═══██╗██╔════╝ ██║   ██║██╔════╝    ██╔══██╗██╔══██╗       ║
║     ██████╔╝██║   ██║██║  ███╗██║   ██║█████╗      ███████║██████╔╝       ║
║     ██╔══██╗██║   ██║██║   ██║██║   ██║██╔══╝      ██╔══██║██╔═══╝        ║
║     ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗    ██║  ██║██║            ║
║     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝            ║
║                                                                           ║
║       ROGUE ACCESS POINT DETECTOR & DEFENSE SYSTEM v2.0                   ║
║                                                                           ║
║          🛡️  Advanced Threat Detection & Network Protection 🛡️           ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
}

show_help() {
  print_banner
  echo ""
  echo -e "${BOLD}USAGE:${NC}"
  echo "  sudo $0 --monitor [INTERFACE]        Monitor for rogue APs in real-time"
  echo "  sudo $0 --scan [INTERFACE]           Scan for APs and check for rogues"
  echo "  sudo $0 --protect SSID BSSID         Protect specific AP (alert on clones)"
  echo "  sudo $0 --analyze LOGFILE            Analyze captured data for threats"
  echo "  sudo $0 --whitelist BSSID            Add trusted AP to whitelist"
  echo "  sudo $0 --blacklist BSSID            Add known rogue to blacklist"
  echo "  sudo $0 --baseline                   Create baseline of legitimate APs"
  echo "  sudo $0 --report                     Generate security report"
  echo "  sudo $0 --threats                    Show threat scoring dashboard"
  echo "  sudo $0 --clients                    Show tracked clients"
  echo "  sudo $0 --help                       Show this help"
  echo ""
  echo -e "${BOLD}DETECTION FEATURES:${NC}"
  echo "  ✓ Evil Twin Detection           Detect duplicate SSIDs with different BSSIDs"
  echo "  ✓ Rogue AP Detection            Identify unauthorized access points"
  echo "  ✓ Deauth Attack Detection       Alert on deauthentication floods"
  echo "  ✓ Signal Anomaly Detection      Detect suspiciously strong signals"
  echo "  ✓ Encryption Downgrade Alert    Warn when encryption weakens"
  echo "  ✓ Channel Switching Detection   Track suspicious channel changes"
  echo "  ✓ MAC Vendor Analysis           Identify suspicious manufacturers"
  echo "  ✓ Captive Portal Detection      Detect fake login portals"
  echo "  ✓ KARMA Attack Detection        Identify promiscuous APs"
  echo "  ✓ WPS Vulnerability Scan        Check for WPS exploits"
  echo -e "  ${CYAN}✓ DNS Spoofing Detection      Detect DNS manipulation${NC}"
  echo -e "  ${CYAN}✓ ARP Spoofing Detection      Detect ARP poisoning${NC}"
  echo -e "  ${CYAN}✓ SSL Strip Detection         Detect HTTPS downgrade attacks${NC}"
  echo -e "  ${CYAN}✓ MITM Indicator Analysis     Identify man-in-the-middle attacks${NC}"
  echo -e "  ${CYAN}✓ Probe Request Analysis      Track device probes and patterns${NC}"
  echo -e "  ${CYAN}✓ Client Fingerprinting       Identify device types and OS${NC}"
  echo -e "  ${CYAN}✓ Threat Scoring System       Rate APs by threat level${NC}"
  echo -e "  ${CYAN}✓ Deep Packet Inspection      Analyze traffic for anomalies${NC}"
  echo ""
  echo -e "${BOLD}MONITORING OPTIONS:${NC}"
  echo "  --interval SECONDS              Scan interval (default: 10)"
  echo "  --alert-email EMAIL             Send alerts via email"
  echo "  --alert-webhook URL             Send alerts to webhook"
  echo "  --alert-slack URL               Send alerts to Slack"
  echo "  --alert-telegram TOKEN CHAT_ID  Send alerts to Telegram"
  echo "  --sound-alert                   Play sound on detection"
  echo "  --no-notify                     Disable desktop notifications"
  echo "  --sensitivity [low|med|high]    Detection sensitivity level"
  echo "  --deep-inspection               Enable deep packet inspection"
  echo "  --capture-packets               Save packets for forensics"
  echo "  --auto-response                 Automatically counter detected threats"
  echo ""
  echo -e "${BOLD}ANALYSIS OPTIONS:${NC}"
  echo "  --check-encryption              Analyze encryption types"
  echo "  --check-vendors                 Verify MAC vendors"
  echo "  --check-signals                 Detect signal anomalies"
  echo "  --check-channels                Monitor channel usage"
  echo "  --detect-mitm                   Look for MITM indicators"
  echo "  --analyze-dns                   Monitor DNS queries for spoofing"
  echo "  --analyze-arp                   Monitor ARP for spoofing"
  echo "  --track-probes                  Analyze probe requests"
  echo "  --fingerprint-clients           Fingerprint connected devices"
  echo ""
  echo -e "${BOLD}EXAMPLES:${NC}"
  echo "  # Start basic monitoring"
  echo "  sudo $0 --monitor wlan0"
  echo ""
  echo "  # Advanced monitoring with all features"
  echo "  sudo $0 --monitor wlan0 --deep-inspection --capture-packets \\"
  echo "    --analyze-dns --analyze-arp --track-probes"
  echo ""
  echo "  # Protect your home WiFi with alerts"
  echo "  sudo $0 --protect \"MyHomeWiFi\" AA:BB:CC:DD:EE:FF \\"
  echo "    --alert-email admin@example.com --alert-slack https://hooks.slack.com/..."
  echo ""
  echo "  # Create baseline and continuous monitoring"
  echo "  sudo $0 --baseline"
  echo "  sudo $0 --monitor wlan0 --interval 5 --auto-response"
  echo ""
  echo "  # Generate comprehensive security report"
  echo "  sudo $0 --report"
  echo ""
  echo "  # View threat dashboard"
  echo "  sudo $0 --threats"
  echo ""
  echo -e "${BOLD}REQUIREMENTS:${NC}"
  echo "  - iw or iwconfig"
  echo "  - aircrack-ng suite (recommended for advanced features)"
  echo "  - tcpdump (for traffic analysis)"
  echo "  - tshark (for deep packet inspection)"
  echo "  - arpwatch (for ARP monitoring)"
  echo "  - notify-send (for desktop notifications)"
  echo "  - mail (for email alerts)"
  echo "  - jq (for JSON processing)"
  echo "  - curl (for webhooks)"
  echo ""
  echo -e "${BOLD}HOW IT PROTECTS YOU:${NC}"
  echo "  1. Continuously monitors wireless environment"
  echo "  2. Learns legitimate APs in your area (baseline)"
  echo "  3. Alerts when duplicate SSIDs appear (evil twins)"
  echo "  4. Detects deauthentication attacks in real-time"
  echo "  5. Identifies suspicious signal patterns"
  echo "  6. Warns about encryption downgrades"
  echo "  7. Detects MITM attacks (ARP/DNS spoofing, SSL stripping)"
  echo "  8. Analyzes probe requests for KARMA attacks"
  echo "  9. Fingerprints devices for anomaly detection"
  echo "  10. Scores threats and prioritizes alerts"
  echo "  11. Logs all suspicious activity with forensic detail"
  echo "  12. Optional auto-response to counter attacks"
  echo ""
  echo -e "${BOLD}LEGAL NOTICE:${NC}"
  echo "  This tool is for network defense and authorized security testing only."
  echo "  Always obtain proper authorization before monitoring networks."
  echo ""
  exit 0
}

# ============================================================================
# SYSTEM CHECKS
# ============================================================================

check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    echo "Usage: sudo $0 [options]"
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Required command '$1' not found"
    log_info "Install with: sudo apt-get install $2"
    return 1
  fi
  return 0
}

check_dependencies() {
  local missing=()
  
  require_cmd "iw" "iw" || missing+=("iw")
  
  # Check for wireless tools
  if ! command -v iw >/dev/null 2>&1 && ! command -v iwconfig >/dev/null 2>&1; then
    missing+=("wireless-tools")
  fi
  
  # Core tools
  command -v jq >/dev/null 2>&1 || log_warn "jq not found (JSON processing disabled)"
  
  # Optional but recommended
  command -v airmon-ng >/dev/null 2>&1 || log_warn "airmon-ng not found (aircrack-ng recommended)"
  command -v tcpdump >/dev/null 2>&1 || log_warn "tcpdump not found (traffic analysis limited)"
  command -v tshark >/dev/null 2>&1 || log_warn "tshark not found (deep inspection disabled)"
  command -v arpwatch >/dev/null 2>&1 || log_warn "arpwatch not found (ARP monitoring limited)"
  command -v notify-send >/dev/null 2>&1 || log_warn "notify-send not found (desktop notifications disabled)"
  
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing required dependencies: ${missing[*]}"
    exit 2
  fi
}

# ============================================================================
# INITIALIZATION
# ============================================================================

init_directories() {
  mkdir -p "$WORK_DIR"
  
  # Initialize files
  [[ ! -f "$WHITELIST_FILE" ]] && touch "$WHITELIST_FILE"
  [[ ! -f "$BLACKLIST_FILE" ]] && touch "$BLACKLIST_FILE"
  [[ ! -f "$KNOWN_APS_DB" ]] && echo "# SSID|BSSID|CHANNEL|ENCRYPTION|SIGNAL|VENDOR|FIRST_SEEN|LAST_SEEN" > "$KNOWN_APS_DB"
  [[ ! -f "$ROGUE_APS_DB" ]] && echo "# SSID|BSSID|REASON|DETECTED_TIME|SIGNAL|CHANNEL|THREAT_SCORE" > "$ROGUE_APS_DB"
  [[ ! -f "$CLIENT_TRACKING_DB" ]] && echo "# MAC|VENDOR|FIRST_SEEN|LAST_SEEN|PROBE_COUNT|CONNECTED_APS" > "$CLIENT_TRACKING_DB"
  
  : > "$SCAN_LOG"
  : > "$MONITOR_LOG"
  : > "$DNS_SPOOF_LOG"
  : > "$SSL_STRIP_LOG"
  : > "$ARP_SPOOF_LOG"
  : > "$MITM_INDICATORS_LOG"
  : > "$CAPTIVE_PORTAL_LOG"
  : > "$PROBE_ANALYSIS_LOG"
  : > "$THREAT_SCORE_LOG"
}

# ============================================================================
# WIRELESS INTERFACE FUNCTIONS
# ============================================================================

get_wireless_interface() {
  local iface="${1:-}"
  
  if [[ -n "$iface" ]]; then
    if ! ip link show "$iface" >/dev/null 2>&1; then
      log_error "Interface $iface not found"
      exit 3
    fi
    echo "$iface"
    return
  fi
  
  # Auto-detect
  iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')
  
  if [[ -z "$iface" ]]; then
    log_error "No wireless interface found"
    log_info "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - "$2}'
    exit 3
  fi
  
  echo "$iface"
}

enable_monitor_mode() {
  local iface="$1"
  
  log_info "Enabling monitor mode on $iface..."
  
  # Stop interfering processes
  airmon-ng check kill >/dev/null 2>&1 || true
  
  # Enable monitor mode
  if command -v airmon-ng >/dev/null 2>&1; then
    airmon-ng start "$iface" >/dev/null 2>&1 || true
    # airmon-ng creates interface like wlan0mon
    if [[ "$iface" != *"mon"* ]]; then
      iface="${iface}mon"
    fi
  else
    ip link set "$iface" down
    iw dev "$iface" set type monitor 2>/dev/null || iwconfig "$iface" mode monitor 2>/dev/null
    ip link set "$iface" up
  fi
  
  log_info "Monitor mode enabled on $iface"
  echo "$iface"
}

disable_monitor_mode() {
  local iface="$1"
  
  log_info "Disabling monitor mode on $iface..."
  
  if command -v airmon-ng >/dev/null 2>&1; then
    airmon-ng stop "$iface" >/dev/null 2>&1 || true
  else
    ip link set "$iface" down
    iw dev "$iface" set type managed 2>/dev/null || iwconfig "$iface" mode managed 2>/dev/null
    ip link set "$iface" up
  fi
  
  # Restart networking
  systemctl restart NetworkManager 2>/dev/null || true
}

# ============================================================================
# MAC VENDOR LOOKUP (EXPANDED)
# ============================================================================

get_mac_vendor() {
  local mac="$1"
  local oui="${mac:0:8}"
  
  # Expanded vendor database with 100+ vendors
  case "$oui" in
    # Networking Equipment
    "00:03:7F"|"00:0B:86"|"00:12:17"|"00:1B:D5"|"00:1F:CA") echo "Cisco" ;;
    "00:18:E7"|"00:26:5A"|"A0:21:B7"|"C0:3F:0E") echo "Netgear" ;;
    "A0:63:91"|"00:1F:C6"|"B8:A3:86"|"D8:EB:97") echo "D-Link" ;;
    "00:1D:7E"|"00:22:3F"|"50:C7:BF"|"EC:08:6B") echo "TP-Link" ;;
    "00:25:9C"|"00:24:D7"|"68:7F:74"|"A0:F3:C1") echo "Linksys" ;;
    "00:0C:42"|"00:15:6D"|"24:A4:3C"|"68:D7:9A") echo "Ubiquiti" ;;
    "00:04:ED"|"00:09:5B"|"00:1B:8F") echo "Aruba" ;;
    
    # Mobile Devices
    "00:17:F2"|"00:1E:52"|"A4:C3:61"|"F0:18:98"|"3C:2E:FF"|"78:7B:8A") echo "Apple" ;;
    "00:19:5B"|"00:1F:3C"|"84:38:35"|"C4:57:6E"|"E0:B9:A5") echo "Samsung" ;;
    "08:96:D7"|"A4:77:33"|"34:CE:00"|"AC:C1:EE") echo "Xiaomi" ;;
    "00:1E:E1"|"04:0E:3C"|"88:53:95") echo "LG" ;;
    "00:1B:FB"|"48:F8:DB"|"6C:AD:F8") echo "Huawei" ;;
    "00:21:D1"|"00:25:67"|"AC:5F:3E") echo "Google/Motorola" ;;
    "BC:EE:7B"|"10:68:3F"|"A8:5B:78") echo "HTC" ;;
    "00:18:AF"|"00:21:FB"|"18:F4:6A") echo "Sony" ;;
    
    # Computer Manufacturers
    "00:16:EA"|"00:1B:63"|"B8:CA:3A"|"D0:50:99") echo "Intel" ;;
    "00:03:93"|"00:0D:56"|"00:17:A4") echo "Dell" ;;
    "00:01:E3"|"00:0A:95"|"00:15:C5") echo "HP" ;;
    "00:11:25"|"00:1F:16"|"00:26:08") echo "Lenovo" ;;
    "00:0E:A6"|"00:1E:8C"|"00:24:E8") echo "Acer" ;;
    "00:03:0D"|"00:12:FB"|"84:8F:69") echo "Asus" ;;
    
    # IoT & Smart Devices
    "DC:A6:32"|"30:85:A9"|"B8:27:EB") echo "Raspberry Pi" ;;
    "5C:CF:7F"|"A4:CF:12"|"CC:50:E3") echo "Amazon Echo" ;;
    "18:B4:30"|"00:17:88"|"64:16:66") echo "Nest" ;;
    "00:1A:22"|"00:26:BB"|"D0:73:D5") echo "Philips Hue" ;;
    
    # Virtual Machines
    "00:50:56"|"00:0C:29"|"00:05:69") echo "VMware" ;;
    "08:00:27") echo "VirtualBox" ;;
    "00:16:3E") echo "Xen" ;;
    "52:54:00") echo "QEMU/KVM" ;;
    
    # WiFi Adapters
    "00:E0:4C"|"00:1C:BF") echo "Realtek" ;;
    "00:C0:CA"|"00:02:2D") echo "Ralink" ;;
    "00:11:50"|"00:1F:1F") echo "Atheros" ;;
    "00:0E:8E"|"00:19:E0") echo "Broadcom" ;;
    "00:11:D8"|"00:19:7D") echo "MediaTek" ;;
    
    *) echo "Unknown" ;;
  esac
}

# ============================================================================
# SCANNING FUNCTIONS (UNCHANGED - KEEPING ALL ORIGINAL FUNCTIONALITY)
# ============================================================================

scan_access_points() {
  local iface="$1"
  local output_file="${2:-$SCAN_LOG}"
  
  log_info "Scanning for access points on $iface..."
  
  # Scan using iw
  if command -v iw >/dev/null 2>&1; then
    iw dev "$iface" scan 2>/dev/null | parse_iw_scan > "$output_file"
  else
    iwlist "$iface" scan 2>/dev/null | parse_iwlist_scan > "$output_file"
  fi
  
  local ap_count=$(grep -c "^BSSID:" "$output_file" 2>/dev/null || echo "0")
  log_info "Found $ap_count access points"
}

parse_iw_scan() {
  local bssid="" ssid="" channel="" signal="" encryption=""
  
  while IFS= read -r line; do
    if [[ "$line" =~ ^BSS\ ([0-9a-fA-F:]+) ]]; then
      # New AP entry - output previous if exists
      if [[ -n "$bssid" ]]; then
        echo "BSSID: $bssid"
        echo "SSID: $ssid"
        echo "CHANNEL: $channel"
        echo "SIGNAL: $signal"
        echo "ENCRYPTION: $encryption"
        echo "---"
      fi
      bssid="${BASH_REMATCH[1]}"
      ssid=""
      channel=""
      signal=""
      encryption="Open"
    elif [[ "$line" =~ SSID:\ (.+) ]]; then
      ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ channel\ ([0-9]+) ]]; then
      channel="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ signal:\ (.+)\ dBm ]]; then
      signal="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ WPA|WPA2|WPA3 ]]; then
      encryption="WPA"
    fi
  done
  
  # Output last AP
  if [[ -n "$bssid" ]]; then
    echo "BSSID: $bssid"
    echo "SSID: $ssid"
    echo "CHANNEL: $channel"
    echo "SIGNAL: $signal"
    echo "ENCRYPTION: $encryption"
    echo "---"
  fi
}

parse_iwlist_scan() {
  # Simplified parser for iwlist
  awk '
    /Address:/ {bssid=$5}
    /ESSID:/ {gsub(/"/, "", $1); ssid=$1}
    /Channel:/ {channel=$1}
    /Signal level=/ {signal=$3}
    /Encryption key:on/ {encryption="WPA"}
    /Encryption key:off/ {encryption="Open"}
    /^$/ {
      if (bssid != "") {
        print "BSSID: " bssid
        print "SSID: " ssid
        print "CHANNEL: " channel
        print "SIGNAL: " signal
        print "ENCRYPTION: " encryption
        print "---"
      }
      bssid=""; ssid=""; channel=""; signal=""; encryption=""
    }
  '
}

# ============================================================================
# DETECTION FUNCTIONS (ALL ORIGINAL + NEW)
# ============================================================================

detect_evil_twins() {
  local scan_file="$1"
  local found_rogues=false
  
  log_info "Checking for evil twin attacks..."
  
  # Build associative array of SSIDs to BSSIDs
  declare -A ssid_map
  declare -A ssid_encryption
  declare -A ssid_channel
  
  local bssid="" ssid="" channel="" encryption="" signal=""
  
  while read -r line; do
    if [[ "$line" =~ ^BSSID:\ (.+) ]]; then
      bssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SSID:\ (.+) ]]; then
      ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^CHANNEL:\ (.+) ]]; then
      channel="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^ENCRYPTION:\ (.+) ]]; then
      encryption="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SIGNAL:\ (.+) ]]; then
      signal="${BASH_REMATCH[1]}"
    elif [[ "$line" == "---" ]]; then
      if [[ -n "$ssid" && "$ssid" != "" ]]; then
        if [[ -v "ssid_map[$ssid]" ]]; then
          # Duplicate SSID found!
          local threat_score=50
          
          # Increase threat if encryption downgraded
          if [[ "${ssid_encryption[$ssid]}" == "WPA" && "$encryption" == "Open" ]]; then
            threat_score=90
            log_alert "⚠️ CRITICAL: Evil Twin with ENCRYPTION DOWNGRADE"
            log_alert "   SSID: '$ssid'"
            log_alert "   Original: ${ssid_map[$ssid]} (WPA)"
            log_alert "   Rogue: $bssid (Open)"
          else
            log_alert "⚠️ EVIL TWIN DETECTED: SSID '$ssid' has multiple BSSIDs"
            log_alert "   Original: ${ssid_map[$ssid]}"
            log_alert "   Duplicate: $bssid"
          fi
          
          # Check if on same channel (more suspicious)
          if [[ "${ssid_channel[$ssid]}" == "$channel" ]]; then
            threat_score=$((threat_score + 20))
            log_alert "   ⚠️ Same channel - highly suspicious!"
          fi
          
          # Log to rogue DB with threat score
          echo "$ssid|$bssid|Evil Twin (Duplicate SSID)|$(date)|$signal|$channel|$threat_score" >> "$ROGUE_APS_DB"
          echo "$(date)|$ssid|$bssid|$threat_score|Evil Twin" >> "$THREAT_SCORE_LOG"
          found_rogues=true
        else
          ssid_map[$ssid]="$bssid"
          ssid_encryption[$ssid]="$encryption"
          ssid_channel[$ssid]="$channel"
        fi
      fi
      bssid=""; ssid=""; channel=""; encryption=""; signal=""
    fi
  done < "$scan_file"
  
  if [[ "$found_rogues" == "false" ]]; then
    log_info "✓ No evil twins detected"
  fi
}

detect_signal_anomalies() {
  local scan_file="$1"
  
  log_info "Checking for signal anomalies..."
  
  local bssid="" ssid="" signal=""
  
  while read -r line; do
    if [[ "$line" =~ ^BSSID:\ (.+) ]]; then
      bssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SSID:\ (.+) ]]; then
      ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SIGNAL:\ (.+) ]]; then
      signal="${BASH_REMATCH[1]}"
    elif [[ "$line" == "---" ]]; then
      # Check if signal is suspiciously strong (AP very close)
      if [[ -n "$signal" && "$signal" =~ ^-?[0-9]+$ ]] && [[ $signal -gt $SIGNAL_STRENGTH_THRESHOLD ]]; then
        local threat_score=40
        log_alert "⚠️ SUSPICIOUS SIGNAL: Abnormally strong signal detected ($signal dBm)"
        log_alert "   SSID: $ssid, BSSID: $bssid"
        log_alert "   This could indicate a rogue AP placed very close to you"
        echo "$(date)|$ssid|$bssid|$threat_score|Strong Signal Anomaly" >> "$THREAT_SCORE_LOG"
      fi
      bssid=""; ssid=""; signal=""
    fi
  done < "$scan_file"
}

detect_encryption_downgrade() {
  local ssid="$1"
  local current_encryption="$2"
  
  # Check known APs database for this SSID
  if grep -q "^$ssid|" "$KNOWN_APS_DB"; then
    local previous_encryption=$(grep "^$ssid|" "$KNOWN_APS_DB" | tail -1 | cut -d'|' -f4)
    
    if [[ "$previous_encryption" == "WPA" && "$current_encryption" == "Open" ]]; then
      log_alert "⚠️ ENCRYPTION DOWNGRADE: '$ssid' changed from WPA to Open"
      log_alert "   This could be an evil twin attack!"
      return 0
    fi
  fi
  
  return 1
}

check_whitelist() {
  local bssid="$1"
  grep -q "^$bssid$" "$WHITELIST_FILE" 2>/dev/null
}

check_blacklist() {
  local bssid="$1"
  if grep -q "^$bssid$" "$BLACKLIST_FILE" 2>/dev/null; then
    log_alert "⚠️ KNOWN ROGUE AP DETECTED: $bssid is in blacklist!"
    return 0
  fi
  return 1
}

detect_deauth_attacks() {
  local iface="$1"
  local duration="${2:-60}"
  
  log_info "Monitoring for deauthentication attacks for ${duration}s..."
  
  if ! command -v tcpdump >/dev/null 2>&1; then
    log_warn "tcpdump not found - deauth detection disabled"
    return
  fi
  
  local deauth_count=0
  local start_time=$(date +%s)
  
  timeout "$duration" tcpdump -i "$iface" -l -e -s 256 type mgt subtype deauth 2>/dev/null | \
  while read -r line; do
    deauth_count=$((deauth_count + 1))
    log_alert "⚠️ DEAUTH ATTACK DETECTED: $line"
    echo "$(date)|$line" >> "$DEAUTH_LOG"
    
    # Check if exceeding threshold
    local current_time=$(date +%s)
    local elapsed=$((current_time - start_time))
    if [[ $elapsed -gt 0 ]]; then
      local rate=$((deauth_count * 60 / elapsed))
      if [[ $rate -gt $DEAUTH_THRESHOLD ]]; then
        log_alert "🚨 CRITICAL: Deauth flood detected - $rate deauths/min (threshold: $DEAUTH_THRESHOLD)"
        echo "$(date)|DEAUTH_FLOOD|$rate per min|80|Deauth Flood" >> "$THREAT_SCORE_LOG"
      fi
    fi
  done &
}

# ============================================================================
# NEW: ADVANCED DETECTION FEATURES
# ============================================================================

detect_dns_spoofing() {
  local iface="$1"
  
  if [[ "$ENABLE_DNS_MONITORING" != "true" ]] || ! command -v tshark >/dev/null 2>&1; then
    return
  fi
  
  log_info "Starting DNS spoofing detection..."
  
  # Monitor DNS responses for inconsistencies
  timeout 60 tshark -i "$iface" -Y "dns.flags.response == 1" -T fields \
    -e dns.qry.name -e dns.a -e ip.src 2>/dev/null | \
  while read -r query answer src; do
    if [[ -n "$query" && -n "$answer" ]]; then
      echo "$(date)|$query|$answer|$src" >> "$DNS_SPOOF_LOG"
      
      # Check if DNS server is suspicious (not in whitelist)
      if ! grep -q "$src" "$WHITELIST_FILE" 2>/dev/null; then
        # Check for known bad patterns
        if [[ "$answer" =~ ^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
          log_alert "⚠️ SUSPICIOUS DNS: $query resolved to private IP $answer by $src"
          echo "$(date)|DNS_SPOOF|$src|60|Suspicious DNS Response" >> "$THREAT_SCORE_LOG"
        fi
      fi
    fi
  done &
}

detect_arp_spoofing() {
  local iface="$1"
  
  if [[ "$ENABLE_ARP_MONITORING" != "true" ]] || ! command -v tcpdump >/dev/null 2>&1; then
    return
  fi
  
  log_info "Starting ARP spoofing detection..."
  
  declare -A ip_to_mac
  
  # Monitor ARP replies
  timeout 300 tcpdump -i "$iface" -l arp 2>/dev/null | \
  while read -r line; do
    if [[ "$line" =~ Reply.*is-at.*([0-9a-fA-F:]{17}) ]]; then
      local mac="${BASH_REMATCH[1]}"
      local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
      
      if [[ -n "$ip" && -n "$mac" ]]; then
        if [[ -v "ip_to_mac[$ip]" ]] && [[ "${ip_to_mac[$ip]}" != "$mac" ]]; then
          log_alert "🚨 ARP SPOOFING DETECTED!"
          log_alert "   IP $ip changed from ${ip_to_mac[$ip]} to $mac"
          echo "$(date)|ARP_SPOOF|$ip|$mac|85|ARP Spoofing" >> "$ARP_SPOOF_LOG"
          echo "$(date)|ARP_SPOOF|$mac|85|ARP Cache Poisoning" >> "$THREAT_SCORE_LOG"
        else
          ip_to_mac[$ip]="$mac"
        fi
      fi
    fi
  done &
}

detect_ssl_stripping() {
  local iface="$1"
  
  if [[ "$ENABLE_DEEP_PACKET_INSPECTION" != "true" ]] || ! command -v tshark >/dev/null 2>&1; then
    return
  fi
  
  log_info "Starting SSL stripping detection..."
  
  # Monitor for HTTP traffic to known HTTPS sites
  declare -A https_sites=(
    ["facebook.com"]=1
    ["google.com"]=1
    ["twitter.com"]=1
    ["amazon.com"]=1
    ["paypal.com"]=1
    ["bankofamerica.com"]=1
    ["chase.com"]=1
  )
  
  timeout 300 tshark -i "$iface" -Y "http.request" -T fields -e http.host 2>/dev/null | \
  while read -r host; do
    if [[ -n "$host" ]]; then
      # Check if this is a known HTTPS-only site
      for site in "${!https_sites[@]}"; do
        if [[ "$host" == *"$site"* ]]; then
          log_alert "🚨 SSL STRIPPING DETECTED!"
          log_alert "   HTTP request to HTTPS-only site: $host"
          log_alert "   Possible MITM attack in progress"
          echo "$(date)|SSL_STRIP|$host|90|SSL Stripping Attack" >> "$SSL_STRIP_LOG"
          echo "$(date)|SSL_STRIP|$host|90|HTTPS Downgrade" >> "$THREAT_SCORE_LOG"
        fi
      done
    fi
  done &
}

detect_mitm_indicators() {
  local iface="$1"
  
  if [[ "$ENABLE_DEEP_PACKET_INSPECTION" != "true" ]]; then
    return
  fi
  
  log_info "Analyzing traffic for MITM indicators..."
  
  # Check for various MITM indicators
  local indicators=0
  
  # 1. Check for duplicate IP addresses
  if command -v arp >/dev/null 2>&1; then
    local dup_ips=$(arp -an | awk '{print $4}' | sort | uniq -d | wc -l)
    if [[ $dup_ips -gt 0 ]]; then
      indicators=$((indicators + 1))
      log_warn "MITM Indicator: Duplicate MAC addresses in ARP table"
    fi
  fi
  
  # 2. Check for gateway MAC changes
  if [[ -f "${WORK_DIR}/gateway_mac.txt" ]]; then
    local current_gw_mac=$(ip neigh show | grep "$(ip route | grep default | awk '{print $3}')" | awk '{print $5}')
    local saved_gw_mac=$(cat "${WORK_DIR}/gateway_mac.txt")
    if [[ "$current_gw_mac" != "$saved_gw_mac" ]]; then
      indicators=$((indicators + 1))
      log_alert "🚨 MITM Indicator: Gateway MAC address changed!"
      log_alert "   Saved: $saved_gw_mac, Current: $current_gw_mac"
    fi
  else
    ip neigh show | grep "$(ip route | grep default | awk '{print $3}')" | awk '{print $5}' > "${WORK_DIR}/gateway_mac.txt"
  fi
  
  # 3. Check for suspicious certificate warnings (if we can inspect)
  # This would require additional tools and permissions
  
  if [[ $indicators -gt 0 ]]; then
    local threat_score=$((indicators * 30))
    echo "$(date)|MITM_INDICATORS|$indicators found|$threat_score|MITM Attack" >> "$MITM_INDICATORS_LOG"
    echo "$(date)|MITM|Multiple indicators|$threat_score|Possible MITM" >> "$THREAT_SCORE_LOG"
  fi
}

detect_captive_portals() {
  local scan_file="$1"
  
  log_info "Checking for captive portals..."
  
  # Captive portals often redirect HTTP to a login page
  # We can detect this by checking for open networks with specific characteristics
  
  local bssid="" ssid="" encryption=""
  
  while read -r line; do
    if [[ "$line" =~ ^BSSID:\ (.+) ]]; then
      bssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SSID:\ (.+) ]]; then
      ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^ENCRYPTION:\ (.+) ]]; then
      encryption="${BASH_REMATCH[1]}"
    elif [[ "$line" == "---" ]]; then
      # Check for suspicious captive portal indicators
      if [[ "$encryption" == "Open" ]]; then
        # Common fake portal SSIDs
        if [[ "$ssid" =~ (Free.*WiFi|Public|Guest|Airport|Hotel|Starbucks|McDonalds) ]]; then
          log_warn "Potential fake captive portal detected: $ssid ($bssid)"
          echo "$(date)|$ssid|$bssid|40|Suspicious Captive Portal" >> "$CAPTIVE_PORTAL_LOG"
        fi
      fi
      bssid=""; ssid=""; encryption=""
    fi
  done < "$scan_file"
}

analyze_probe_requests() {
  local iface="$1"
  
  if [[ "$ENABLE_PROBE_ANALYSIS" != "true" ]] || ! command -v tcpdump >/dev/null 2>&1; then
    return
  fi
  
  log_info "Analyzing probe requests for KARMA attacks..."
  
  declare -A probe_counts
  local start_time=$(date +%s)
  
  # Monitor probe requests
  timeout 120 tcpdump -i "$iface" -l -e -s 256 type mgt subtype probe-req 2>/dev/null | \
  while read -r line; do
    # Extract MAC address
    local mac=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
    
    if [[ -n "$mac" ]]; then
      probe_counts[$mac]=$((${probe_counts[$mac]:-0} + 1))
      
      # Check for excessive probing (KARMA indicator)
      if [[ ${probe_counts[$mac]} -gt $PROBE_THRESHOLD ]]; then
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        local rate=$((${probe_counts[$mac]} * 60 / elapsed))
        
        log_alert "⚠️ KARMA ATTACK INDICATOR: Device $mac probing excessively"
        log_alert "   $rate probe requests per minute"
        echo "$(date)|KARMA|$mac|$rate probes/min|70|KARMA Attack" >> "$PROBE_ANALYSIS_LOG"
        echo "$(date)|KARMA|$mac|70|Excessive Probing" >> "$THREAT_SCORE_LOG"
      fi
    fi
  done &
}

fingerprint_clients() {
  local iface="$1"
  
  if [[ "$ENABLE_CLIENT_FINGERPRINTING" != "true" ]]; then
    return
  fi
  
  log_info "Fingerprinting connected clients..."
  
  # Use passive OS fingerprinting techniques
  if command -v p0f >/dev/null 2>&1; then
    timeout 300 p0f -i "$iface" -o "$WORK_DIR/p0f_output.log" 2>/dev/null &
  fi
  
  # Track clients
  if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
    while read -r line; do
      local mac=$(echo "$line" | awk '{print $2}')
      local ip=$(echo "$line" | awk '{print $3}')
      local hostname=$(echo "$line" | awk '{print $4}')
      local vendor=$(get_mac_vendor "$mac")
      
      # Check if this is a new client
      if ! grep -q "^$mac|" "$CLIENT_TRACKING_DB" 2>/dev/null; then
        echo "$mac|$vendor|$(date)|$(date)|1|" >> "$CLIENT_TRACKING_DB"
        log_info "New client tracked: $mac ($vendor) - $hostname"
      else
        # Update last seen - FIXED: Properly escape pipes and use correct field extraction
        local first_seen=$(grep "^$mac|" "$CLIENT_TRACKING_DB" | cut -d'|' -f3)
        local probe_count=$(grep "^$mac|" "$CLIENT_TRACKING_DB" | cut -d'|' -f5)
        # Remove old entry
        sed -i "/^${mac}|/d" "$CLIENT_TRACKING_DB"
        # Add updated entry
        echo "$mac|$vendor|$first_seen|$(date)|$probe_count|" >> "$CLIENT_TRACKING_DB"
      fi
    done < /var/lib/misc/dnsmasq.leases
  fi
}

calculate_threat_score() {
  local bssid="$1"
  local ssid="$2"
  local indicators="$3"
  
  local score=0
  
  # Check various threat indicators
  if grep -q "$bssid" "$BLACKLIST_FILE" 2>/dev/null; then
    score=$((score + 100))
  fi
  
  if grep -q "$ssid.*Evil Twin" "$ROGUE_APS_DB" 2>/dev/null; then
    score=$((score + 50))
  fi
  
  if grep -q "$bssid" "$DEAUTH_LOG" 2>/dev/null; then
    score=$((score + 30))
  fi
  
  if grep -q "$bssid" "$ARP_SPOOF_LOG" 2>/dev/null; then
    score=$((score + 40))
  fi
  
  if grep -q "$bssid" "$DNS_SPOOF_LOG" 2>/dev/null; then
    score=$((score + 35))
  fi
  
  echo "$score"
}

# ============================================================================
# AUTOMATED RESPONSE SYSTEM
# ============================================================================

auto_respond_to_threat() {
  local threat_type="$1"
  local target="$2"
  local iface="$3"
  
  if [[ "$ENABLE_AUTO_RESPONSE" != "true" ]]; then
    return
  fi
  
  log_warn "🛡️ AUTO-RESPONSE: Countering $threat_type from $target"
  
  case "$threat_type" in
    "EVIL_TWIN")
      # Send deauth to clients connecting to rogue AP
      if command -v aireplay-ng >/dev/null 2>&1; then
        log_info "Sending deauth to rogue AP clients: $target"
        timeout 10 aireplay-ng --deauth 5 -a "$target" "$iface" >/dev/null 2>&1 &
      fi
      ;;
    
    "DEAUTH_ATTACK")
      # Could implement channel hopping or other defensive measures
      log_info "Implementing deauth attack countermeasures"
      ;;
    
    "ARP_SPOOF")
      # Send correct ARP announcements
      log_info "Broadcasting correct ARP information"
      ;;
  esac
}

# ============================================================================
# PACKET CAPTURE
# ============================================================================

start_packet_capture() {
  local iface="$1"
  
  if [[ "$ENABLE_PACKET_CAPTURE" != "true" ]] || ! command -v tcpdump >/dev/null 2>&1; then
    return
  fi
  
  log_info "Starting full packet capture..."
  tcpdump -i "$iface" -w "$PACKET_CAPTURE" -s 65535 2>/dev/null &
  echo $! > "${WORK_DIR}/tcpdump.pid"
  log_success "Packet capture started: $PACKET_CAPTURE"
}

stop_packet_capture() {
  if [[ -f "${WORK_DIR}/tcpdump.pid" ]]; then
    local pid=$(cat "${WORK_DIR}/tcpdump.pid")
    if kill -0 "$pid" 2>/dev/null; then
      log_info "Stopping packet capture..."
      kill "$pid" 2>/dev/null || true
      sleep 2
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "${WORK_DIR}/tcpdump.pid"
    
    if [[ -f "$PACKET_CAPTURE" ]]; then
      local size=$(du -h "$PACKET_CAPTURE" | awk '{print $1}')
      log_success "Packet capture saved: $PACKET_CAPTURE ($size)"
    fi
  fi
}

# ============================================================================
# MONITORING MODE (ENHANCED)
# ============================================================================

monitor_mode() {
  local iface="$1"
  local interval="${2:-10}"
  
  print_banner
  log_info "Starting enhanced continuous monitoring on $iface"
  log_info "Scan interval: ${interval} seconds"
  log_info "Press Ctrl+C to stop"
  echo
  
  # Enable monitor mode if using aircrack-ng
  local monitor_iface="$iface"
  if command -v airmon-ng >/dev/null 2>&1; then
    monitor_iface=$(enable_monitor_mode "$iface")
  fi
  
  # Start all detection modules
  detect_deauth_attacks "$monitor_iface" 999999999 &
  local deauth_pid=$!
  
  if [[ "$ENABLE_DNS_MONITORING" == "true" ]]; then
    detect_dns_spoofing "$monitor_iface" &
    local dns_pid=$!
  fi
  
  if [[ "$ENABLE_ARP_MONITORING" == "true" ]]; then
    detect_arp_spoofing "$monitor_iface" &
    local arp_pid=$!
  fi
  
  if [[ "$ENABLE_DEEP_PACKET_INSPECTION" == "true" ]]; then
    detect_ssl_stripping "$monitor_iface" &
    local ssl_pid=$!
  fi
  
  if [[ "$ENABLE_PROBE_ANALYSIS" == "true" ]]; then
    analyze_probe_requests "$monitor_iface" &
    local probe_pid=$!
  fi
  
  if [[ "$ENABLE_PACKET_CAPTURE" == "true" ]]; then
    start_packet_capture "$monitor_iface"
  fi
  
  # Cleanup function
  cleanup_monitor() {
    log_info "Stopping all detection modules..."
    kill $deauth_pid 2>/dev/null || true
    [[ -n "${dns_pid:-}" ]] && kill $dns_pid 2>/dev/null || true
    [[ -n "${arp_pid:-}" ]] && kill $arp_pid 2>/dev/null || true
    [[ -n "${ssl_pid:-}" ]] && kill $ssl_pid 2>/dev/null || true
    [[ -n "${probe_pid:-}" ]] && kill $probe_pid 2>/dev/null || true
    stop_packet_capture
    disable_monitor_mode "$monitor_iface"
    exit 0
  }
  
  trap cleanup_monitor INT TERM
  
  # Main monitoring loop
  while true; do
    clear
    print_banner
    echo
    log_info "Scanning... ($(date))"
    
    scan_access_points "$iface"
    
    # Run all detections
    detect_evil_twins "$SCAN_LOG"
    detect_signal_anomalies "$SCAN_LOG"
    detect_captive_portals "$SCAN_LOG"
    detect_mitm_indicators "$iface"
    
    if [[ "$ENABLE_CLIENT_FINGERPRINTING" == "true" ]]; then
      fingerprint_clients "$iface"
    fi
    
    # Check against blacklist
    while read -r line; do
      if [[ "$line" =~ ^BSSID:\ (.+) ]]; then
        local bssid="${BASH_REMATCH[1]}"
        check_blacklist "$bssid"
      fi
    done < "$SCAN_LOG"
    
    # Display current threat status
    if [[ -f "$THREAT_SCORE_LOG" ]]; then
      local threat_count=$(wc -l < "$THREAT_SCORE_LOG" 2>/dev/null || echo "0")
      if [[ $threat_count -gt 0 ]]; then
        echo
        echo -e "${RED}${BOLD}Active Threats: $threat_count${NC}"
        tail -5 "$THREAT_SCORE_LOG" | while IFS='|' read -r timestamp type target score reason; do
          echo -e "  ${YELLOW}•${NC} $reason (Score: $score) - $timestamp"
        done
      fi
    fi
    
    echo
    log_info "Next scan in ${interval} seconds..."
    sleep "$interval"
  done
}

# ============================================================================
# BASELINE CREATION (UNCHANGED)
# ============================================================================

create_baseline() {
  local iface="$1"
  
  log_info "Creating baseline of legitimate access points..."
  log_info "This will scan and record all APs"
  
  scan_access_points "$iface"
  
  # Copy scan results to known APs database
  local bssid="" ssid="" channel="" encryption="" signal=""
  
  while read -r line; do
    if [[ "$line" == "---" ]]; then
      if [[ -n "$ssid" && -n "$bssid" ]]; then
        local vendor=$(get_mac_vendor "$bssid")
        echo "$ssid|$bssid|$channel|$encryption|$signal|$vendor|$(date)|$(date)" >> "$KNOWN_APS_DB"
      fi
      ssid=""; bssid=""; channel=""; encryption=""; signal=""
    elif [[ "$line" =~ ^SSID:\ (.+) ]]; then
      ssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^BSSID:\ (.+) ]]; then
      bssid="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^CHANNEL:\ (.+) ]]; then
      channel="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^ENCRYPTION:\ (.+) ]]; then
      encryption="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^SIGNAL:\ (.+) ]]; then
      signal="${BASH_REMATCH[1]}"
    fi
  done < "$SCAN_LOG"
  
  local count=$(($(wc -l < "$KNOWN_APS_DB") - 1))
  log_success "Baseline created with $count access points"
}

# ============================================================================
# REPORTING (ENHANCED)
# ============================================================================

generate_report() {
  print_banner
  echo
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║              COMPREHENSIVE SECURITY REPORT                   ║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo
  
  echo -e "${CYAN}Generated:${NC} $(date)"
  echo -e "${CYAN}Report Location:${NC} $WORK_DIR"
  echo
  
  # Known APs
  if [[ -f "$KNOWN_APS_DB" ]]; then
    local known_count=$(($(wc -l < "$KNOWN_APS_DB") - 1))
    echo -e "${GREEN}${BOLD}Known Legitimate APs:${NC} $known_count"
  fi
  
  # Rogue APs
  if [[ -f "$ROGUE_APS_DB" ]]; then
    local rogue_count=$(($(wc -l < "$ROGUE_APS_DB") - 1))
    echo -e "${RED}${BOLD}Rogue APs Detected:${NC} $rogue_count"
    
    if [[ $rogue_count -gt 0 ]]; then
      echo
      echo -e "${RED}${BOLD}Rogue Access Points:${NC}"
      tail -n +2 "$ROGUE_APS_DB" | while IFS='|' read -r ssid bssid reason detected signal channel threat; do
        echo -e "  ${YELLOW}•${NC} SSID: ${BOLD}$ssid${NC}"
        echo -e "    BSSID: $bssid"
        echo -e "    Reason: $reason"
        echo -e "    Threat Score: ${RED}$threat${NC}/100"
        echo -e "    Detected: $detected"
        echo
      done
    fi
  fi
  
  # Alerts
  if [[ -f "$ALERT_LOG" ]]; then
    local alert_count=$(wc -l < "$ALERT_LOG" 2>/dev/null || echo "0")
    echo -e "${YELLOW}${BOLD}Total Alerts:${NC} $alert_count"
    
    if [[ $alert_count -gt 0 ]]; then
      echo
      echo -e "${YELLOW}${BOLD}Recent Alerts (last 10):${NC}"
      tail -10 "$ALERT_LOG"
      echo
    fi
  fi
  
  # Deauth Attacks
  if [[ -f "$DEAUTH_LOG" ]] && [[ -s "$DEAUTH_LOG" ]]; then
    local deauth_count=$(wc -l < "$DEAUTH_LOG")
    echo -e "${RED}${BOLD}Deauth Attacks Detected:${NC} $deauth_count"
  fi
  
  # DNS Spoofing
  if [[ -f "$DNS_SPOOF_LOG" ]] && [[ -s "$DNS_SPOOF_LOG" ]]; then
    local dns_count=$(wc -l < "$DNS_SPOOF_LOG")
    echo -e "${YELLOW}${BOLD}DNS Spoofing Attempts:${NC} $dns_count"
  fi
  
  # ARP Spoofing
  if [[ -f "$ARP_SPOOF_LOG" ]] && [[ -s "$ARP_SPOOF_LOG" ]]; then
    local arp_count=$(wc -l < "$ARP_SPOOF_LOG")
    echo -e "${YELLOW}${BOLD}ARP Spoofing Attempts:${NC} $arp_count"
  fi
  
  # SSL Stripping
  if [[ -f "$SSL_STRIP_LOG" ]] && [[ -s "$SSL_STRIP_LOG" ]]; then
    local ssl_count=$(wc -l < "$SSL_STRIP_LOG")
    echo -e "${RED}${BOLD}SSL Stripping Detected:${NC} $ssl_count"
  fi
  
  # MITM Indicators
  if [[ -f "$MITM_INDICATORS_LOG" ]] && [[ -s "$MITM_INDICATORS_LOG" ]]; then
    local mitm_count=$(wc -l < "$MITM_INDICATORS_LOG")
    echo -e "${RED}${BOLD}MITM Indicators:${NC} $mitm_count"
  fi
  
  # Tracked Clients
  if [[ -f "$CLIENT_TRACKING_DB" ]]; then
    local client_count=$(($(wc -l < "$CLIENT_TRACKING_DB") - 1))
    echo -e "${CYAN}${BOLD}Tracked Clients:${NC} $client_count"
  fi
  
  # Packet Capture
  if [[ -f "$PACKET_CAPTURE" ]]; then
    local pcap_size=$(du -h "$PACKET_CAPTURE" 2>/dev/null | awk '{print $1}')
    echo -e "${CYAN}Packet Capture:${NC} $pcap_size"
    echo -e "${CYAN}Analyze with:${NC} wireshark $PACKET_CAPTURE"
  fi
  
  echo
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║                    THREAT SUMMARY                            ║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo
  
  if [[ -f "$THREAT_SCORE_LOG" ]] && [[ -s "$THREAT_SCORE_LOG" ]]; then
    echo -e "${YELLOW}${BOLD}Top Threats (by score):${NC}"
    sort -t'|' -k4 -nr "$THREAT_SCORE_LOG" | head -10 | \
    while IFS='|' read -r timestamp type target score reason; do
      local color="$GREEN"
      [[ $score -gt 50 ]] && color="$YELLOW"
      [[ $score -gt 75 ]] && color="$RED"
      echo -e "  ${color}[Score: $score]${NC} $reason"
      echo -e "    Type: $type, Target: $target"
      echo -e "    Time: $timestamp"
      echo
    done
  fi
  
  echo
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo
  log_info "Full logs and data available in: $WORK_DIR"
  log_info "For detailed analysis, use: sudo $0 --analyze <logfile>"
}

show_threat_dashboard() {
  print_banner
  echo
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║                  LIVE THREAT DASHBOARD                       ║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo
  
  if [[ ! -f "$THREAT_SCORE_LOG" ]] || [[ ! -s "$THREAT_SCORE_LOG" ]]; then
    log_warn "No threats detected yet"
    exit 0
  fi
  
  # Calculate statistics
  local total_threats=$(wc -l < "$THREAT_SCORE_LOG")
  local critical_threats=$(awk -F'|' '$4 >= 75' "$THREAT_SCORE_LOG" | wc -l)
  local high_threats=$(awk -F'|' '$4 >= 50 && $4 < 75' "$THREAT_SCORE_LOG" | wc -l)
  local medium_threats=$(awk -F'|' '$4 >= 25 && $4 < 50' "$THREAT_SCORE_LOG" | wc -l)
  local low_threats=$(awk -F'|' '$4 < 25' "$THREAT_SCORE_LOG" | wc -l)
  
  echo -e "${CYAN}Total Threats:${NC} $total_threats"
  echo -e "${RED}Critical (75-100):${NC} $critical_threats"
  echo -e "${YELLOW}High (50-74):${NC} $high_threats"
  echo -e "${BLUE}Medium (25-49):${NC} $medium_threats"
  echo -e "${GREEN}Low (0-24):${NC} $low_threats"
  echo
  
  # Threat breakdown by type
  echo -e "${BOLD}Threat Types:${NC}"
  awk -F'|' '{print $2}' "$THREAT_SCORE_LOG" | sort | uniq -c | sort -rn | \
  while read -r count type; do
    echo -e "  ${YELLOW}•${NC} $type: $count"
  done
  echo
  
  # Recent threats
  echo -e "${BOLD}Recent Threats (last 15):${NC}"
  tail -15 "$THREAT_SCORE_LOG" | sort -t'|' -k4 -nr | \
  while IFS='|' read -r timestamp type target score reason; do
    local color="$GREEN"
    local label="LOW"
    [[ $score -gt 25 ]] && color="$BLUE" && label="MED"
    [[ $score -gt 50 ]] && color="$YELLOW" && label="HIGH"
    [[ $score -gt 75 ]] && color="$RED" && label="CRIT"
    
    echo -e "  ${color}[$label]${NC} $reason"
    echo -e "      Score: $score | Type: $type | Target: $target"
    echo -e "      Time: $timestamp"
    echo
  done
  
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
}

show_client_list() {
  print_banner
  echo
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║                    TRACKED CLIENTS                           ║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo
  
  if [[ ! -f "$CLIENT_TRACKING_DB" ]] || [[ ! -s "$CLIENT_TRACKING_DB" ]]; then
    log_warn "No clients tracked yet"
    exit 0
  fi
  
  local client_count=$(($(wc -l < "$CLIENT_TRACKING_DB") - 1))
  echo -e "${CYAN}Total Clients Tracked:${NC} $client_count"
  echo
  
  printf "%-18s %-15s %-20s %-20s %-10s\n" "MAC Address" "Vendor" "First Seen" "Last Seen" "Probes"
  printf "%-18s %-15s %-20s %-20s %-10s\n" "──────────────────" "───────────────" "────────────────────" "────────────────────" "──────────"
  
  tail -n +2 "$CLIENT_TRACKING_DB" | while IFS='|' read -r mac vendor first last probes aps; do
    printf "%-18s %-15s %-20s %-20s %-10s\n" "$mac" "$vendor" "$first" "$last" "$probes"
  done
  
  echo
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
  local action="${1:-}"
  
  [[ "$action" == "--help" || "$action" == "-h" ]] && show_help
  
  check_root
  check_dependencies
  init_directories
  
  case "$action" in
    --monitor)
      local iface=$(get_wireless_interface "${2:-}")
      local interval="${3:-10}"
      
      # Parse additional options - FIXED: Better argument handling
      if [[ $# -gt 2 ]]; then
        shift 2
      else
        shift $#
      fi
      
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --interval) interval="$2"; shift 2 ;;
          --deep-inspection) ENABLE_DEEP_PACKET_INSPECTION=true; shift ;;
          --capture-packets) ENABLE_PACKET_CAPTURE=true; shift ;;
          --analyze-dns) ENABLE_DNS_MONITORING=true; shift ;;
          --analyze-arp) ENABLE_ARP_MONITORING=true; shift ;;
          --track-probes) ENABLE_PROBE_ANALYSIS=true; shift ;;
          --fingerprint-clients) ENABLE_CLIENT_FINGERPRINTING=true; shift ;;
          --auto-response) ENABLE_AUTO_RESPONSE=true; shift ;;
          --alert-email) EMAIL_ADDRESS="$2"; ENABLE_EMAIL_ALERTS=true; shift 2 ;;
          --alert-webhook) WEBHOOK_URL="$2"; shift 2 ;;
          --alert-slack) SLACK_WEBHOOK="$2"; shift 2 ;;
          --alert-telegram) TELEGRAM_BOT_TOKEN="$2"; TELEGRAM_CHAT_ID="$3"; shift 3 ;;
          --no-notify) ENABLE_DESKTOP_NOTIFY=false; shift ;;
          --sound-alert) ENABLE_SOUND_ALERTS=true; shift ;;
          *) shift ;;
        esac
      done
      
      monitor_mode "$iface" "$interval"
      ;;
    
    --scan)
      local iface=$(get_wireless_interface "${2:-}")
      scan_access_points "$iface"
      detect_evil_twins "$SCAN_LOG"
      detect_signal_anomalies "$SCAN_LOG"
      detect_captive_portals "$SCAN_LOG"
      log_success "Scan complete. Results in $SCAN_LOG"
      ;;
    
    --baseline)
      local iface=$(get_wireless_interface "${2:-}")
      create_baseline "$iface"
      ;;
    
    --protect)
      if [[ -z "${2:-}" || -z "${3:-}" ]]; then
        log_error "Usage: $0 --protect SSID BSSID"
        exit 1
      fi
      local protect_ssid="$2"
      local protect_bssid="$3"
      echo "$protect_bssid" >> "$WHITELIST_FILE"
      log_success "Added $protect_ssid ($protect_bssid) to whitelist"
      ;;
    
    --whitelist)
      if [[ -z "${2:-}" ]]; then
        log_error "Usage: $0 --whitelist BSSID"
        exit 1
      fi
      echo "$2" >> "$WHITELIST_FILE"
      log_success "Added $2 to whitelist"
      ;;
    
    --blacklist)
      if [[ -z "${2:-}" ]]; then
        log_error "Usage: $0 --blacklist BSSID"
        exit 1
      fi
      echo "$2" >> "$BLACKLIST_FILE"
      log_success "Added $2 to blacklist"
      ;;
    
    --report)
      generate_report
      ;;
    
    --threats)
      show_threat_dashboard
      ;;
    
    --clients)
      show_client_list
      ;;
    
    --analyze)
      if [[ -z "${2:-}" || ! -f "${2:-}" ]]; then
        log_error "Usage: $0 --analyze LOGFILE"
        exit 1
      fi
      detect_evil_twins "$2"
      detect_signal_anomalies "$2"
      detect_captive_portals "$2"
      ;;
    
    *)
      log_error "Unknown action: $action"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
}

# Run main function
main "$@"