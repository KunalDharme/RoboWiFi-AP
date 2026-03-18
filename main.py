#!/usr/bin/env python3
"""
RoboWiFi-AP - WiFi Security Assessment Framework
A tool for authorized penetration testing and security research
"""

import os
import sys
import shutil
import shlex          # FIX 7: needed for safe arg splitting
import subprocess
from pathlib import Path
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from time import sleep

# Initialize colorama
init(autoreset=True)

# Configuration
SCRIPT_DIR = Path(__file__).parent

# FIX 1: Use scripts directly from project directory — no copy needed
# Copying to ~/.robowifi caused stale scripts and edits not taking effect
LOCAL_SCRIPTS = {
    "basic":    SCRIPT_DIR / "scripts" / "fake_ap.sh",
    "advanced": SCRIPT_DIR / "scripts" / "advanced_fake_ap.sh",
    "defender": SCRIPT_DIR / "scripts" / "fake_ap_detector.sh",
}

SCRIPT_NAMES = {
    "basic":    "fake_ap.sh",
    "advanced": "advanced_fake_ap.sh",
    "defender": "fake_ap_detector.sh",
}

SETUP_SCRIPT = SCRIPT_DIR / "setup.sh"
TEST_SCRIPT  = SCRIPT_DIR / "test.sh"


def clear():
    """Clear the terminal screen"""
    os.system("clear" if os.name == "posix" else "cls")


def print_logo():
    """Banner — shown only on first launch, not on every menu redraw"""
    console = Console()
    console.clear()

    title = Text("ROBO", style="bold red")
    title.append("WIFI", style="bold white")
    title.append("-AP", style="bold red")

    wifi = Text("\n📡  ACCESS POINT ACTIVE\n", style="red")

    subtitle = Text(
        "WiFi Security Assessment Framework\n",
        style="bright_red"
    )

    content = Align.center(
        Text.assemble(title, "\n", wifi, subtitle),
        vertical="middle"
    )

    panel = Panel(
        content,
        border_style="bright_red",
        padding=(1, 4),
        title="System Boot",
        title_align="center"
    )

    console.print(panel)
    # FIX 6: sleep only on first launch — moved to caller (main)


def show_disclaimer():
    """Display legal disclaimer and get user acceptance"""
    clear()
    print_logo()

    print(f"\n{Fore.RED}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.RED}                    ⚠️  LEGAL DISCLAIMER  ⚠️{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*65}{Style.RESET_ALL}\n")

    disclaimer_text = f"""{Fore.WHITE}This tool is designed for AUTHORIZED security testing and
educational purposes ONLY.

{Fore.YELLOW}YOU MUST HAVE EXPLICIT WRITTEN PERMISSION before using this tool
on any network you do not own.

{Fore.WHITE}By using this software, you agree that:

{Fore.CYAN}  1. {Fore.WHITE}You will ONLY use this tool on networks you own or have
     written authorization to test

{Fore.CYAN}  2. {Fore.WHITE}You understand that unauthorized access to computer networks
     is illegal in most jurisdictions

{Fore.CYAN}  3. {Fore.WHITE}You are solely responsible for your actions and any
     consequences that result from using this tool

{Fore.CYAN}  4. {Fore.WHITE}The authors and contributors assume NO LIABILITY for misuse
     of this software

{Fore.CYAN}  5. {Fore.WHITE}You will comply with all applicable laws and regulations

{Fore.RED}UNAUTHORIZED USE OF THIS TOOL MAY RESULT IN CRIMINAL PROSECUTION.

{Fore.WHITE}If you do not agree with these terms, exit now.{Style.RESET_ALL}
"""

    print(disclaimer_text)
    print(f"{Fore.RED}{'='*65}{Style.RESET_ALL}\n")

    while True:
        response = input(
            f"{Fore.YELLOW}Do you accept these terms? (yes/no): {Style.RESET_ALL}"
        ).strip().lower()

        if response in ['yes', 'y']:
            print(f"\n{Fore.GREEN}✓ Terms accepted. Proceeding...{Style.RESET_ALL}\n")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return  # FIX 2: just return, no bool needed — exits via sys.exit on 'no'
        elif response in ['no', 'n']:
            print(f"\n{Fore.RED}Terms not accepted. Exiting...{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid input. Please type 'yes' or 'no'.{Style.RESET_ALL}")


def show_guide():
    """Display tool guide — shown only on first launch"""
    clear()

    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}                        TOOL GUIDE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

    guide_text = f"""{Fore.WHITE}RoboWiFi-AP provides four operational modes:

{Fore.YELLOW}0. SETUP & CHECK REQUIREMENTS{Style.RESET_ALL}
{Fore.WHITE}   • Install all required dependencies
   • Check system compatibility
   • Verify wireless adapter capabilities
   • Configure system settings
   • Run diagnostic tests

   {Fore.YELLOW}Use Case:{Fore.WHITE} First-time setup, troubleshooting, system verification

{Fore.GREEN}1. BASIC FAKE ACCESS POINT{Style.RESET_ALL}
{Fore.WHITE}   • Create simple fake WiFi access points
   • Capture WPA2 passwords (with hostapd-wpe)
   • Internet sharing capabilities
   • DHCP and DNS services
   • Real-time client monitoring

   {Fore.YELLOW}Use Case:{Fore.WHITE} Basic penetration testing, credential harvesting,
             testing client behavior

{Fore.CYAN}2. ADVANCED FAKE ACCESS POINT{Style.RESET_ALL}
{Fore.WHITE}   • All basic features PLUS:
   • Captive portal for credential harvesting
   • Packet monitoring with tcpdump
   • MAC address filtering (whitelist/blacklist)
   • Bandwidth limiting per client
   • Hidden SSID (stealth mode)
   • Comprehensive logging and analysis

   {Fore.YELLOW}Use Case:{Fore.WHITE} Advanced penetration testing, complex attack
             scenarios, detailed traffic analysis

{Fore.MAGENTA}3. ROGUE AP DETECTOR (DEFENDER){Style.RESET_ALL}
{Fore.WHITE}   • Detect rogue/fake access points
   • Monitor for evil twin attacks
   • Identify deauthentication attacks
   • ARP spoofing detection
   • DNS spoofing detection
   • Real-time threat alerts
   • Client tracking and analysis

   {Fore.YELLOW}Use Case:{Fore.WHITE} Network defense, security monitoring, detecting
             malicious access points

{Fore.RED}⚠️  IMPORTANT NOTES:{Style.RESET_ALL}
{Fore.WHITE}   • Requires root/sudo privileges
   • Run setup (option 0) before first use
   • Wireless adapter must support AP mode (for offensive modes)
   • Some features require additional tools (hostapd-wpe, tcpdump)
   • Always ensure you have proper authorization
   • Keep logs secure and delete after use{Style.RESET_ALL}
"""

    print(guide_text)
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")
    input(f"{Fore.CYAN}Press ENTER to continue to main menu...{Style.RESET_ALL}")


def show_main_menu():
    """Display main menu and get user choice"""
    while True:
        # FIX 6: Don't call print_logo() here — it added sleep(1) on every loop
        clear()
        print(f"\n{Fore.RED}{'─'*65}{Style.RESET_ALL}")
        print(f"{Fore.RED}  RoboWiFi-AP  •  WiFi Security Assessment Framework{Style.RESET_ALL}")
        print(f"{Fore.RED}{'─'*65}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                       MAIN MENU{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        menu_text = f"""{Fore.YELLOW}[0]{Fore.WHITE} Setup & Check Requirements
    {Fore.YELLOW}→{Fore.WHITE} Install dependencies and verify system readiness

{Fore.GREEN}[1]{Fore.WHITE} Basic Fake Access Point
    {Fore.YELLOW}→{Fore.WHITE} Create simple fake AP with password capture

{Fore.CYAN}[2]{Fore.WHITE} Advanced Fake Access Point
    {Fore.YELLOW}→{Fore.WHITE} Full-featured AP with captive portal & monitoring

{Fore.MAGENTA}[3]{Fore.WHITE} Rogue AP Detector (Defender Mode)
    {Fore.YELLOW}→{Fore.WHITE} Detect and defend against fake access points

{Fore.RED}[4]{Fore.WHITE} Exit
    {Fore.YELLOW}→{Fore.WHITE} Exit the program
"""
        print(menu_text)
        print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

        choice = input(f"{Fore.YELLOW}Select an option [0-4]: {Style.RESET_ALL}").strip()

        if choice == '0':
            return 'setup'
        elif choice == '1':
            return 'basic'
        elif choice == '2':
            return 'advanced'
        elif choice == '3':
            return 'defender'
        elif choice == '4':
            print(f"\n{Fore.CYAN}Exiting... Stay safe!{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}Invalid option. Please select 0-4.{Style.RESET_ALL}")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")


def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        print(f"\n{Fore.RED}ERROR: This tool requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please run with: sudo python3 {sys.argv[0]}{Style.RESET_ALL}\n")
        sys.exit(1)


def run_setup():
    """Run the setup script to install dependencies"""
    clear()

    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}              SETUP & REQUIREMENTS CHECK{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

    print(f"{Fore.WHITE}This will:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  • Install required packages (hostapd, dnsmasq, etc.)")
    print(f"{Fore.CYAN}  • Check wireless adapter compatibility")
    print(f"{Fore.CYAN}  • Configure system settings")
    print(f"{Fore.CYAN}  • Optionally install hostapd-wpe for password capture")
    print(f"{Fore.CYAN}  • Run system diagnostics\n")

    if not SETUP_SCRIPT.exists():
        print(f"{Fore.RED}ERROR: Setup script not found at {SETUP_SCRIPT}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please ensure setup.sh is in the same directory.{Style.RESET_ALL}\n")
        input(f"{Fore.CYAN}Press ENTER to return to menu...{Style.RESET_ALL}")
        return False

    print(f"{Fore.YELLOW}Setup Options:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[1] Full setup (install all dependencies)")
    print(f"{Fore.WHITE}[2] Full setup + hostapd-wpe (for password capture)")
    print(f"{Fore.WHITE}[3] Quick check only (verify system without installing)")
    print(f"{Fore.WHITE}[4] Cancel and return to menu\n")

    while True:
        setup_choice = input(
            f"{Fore.YELLOW}Select setup option [1-4]: {Style.RESET_ALL}"
        ).strip()

        if setup_choice == '1':
            print(f"\n{Fore.GREEN}Starting full setup...{Style.RESET_ALL}\n")
            try:
                result = subprocess.run(["bash", str(SETUP_SCRIPT)], check=False)
                if result.returncode == 0:
                    print(f"\n{Fore.GREEN}✓ Setup completed successfully!{Style.RESET_ALL}\n")
                else:
                    print(f"\n{Fore.YELLOW}⚠ Setup completed with warnings.{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}ERROR: Setup failed: {e}{Style.RESET_ALL}\n")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True

        elif setup_choice == '2':
            print(f"\n{Fore.GREEN}Starting full setup with hostapd-wpe...{Style.RESET_ALL}\n")
            try:
                result = subprocess.run(
                    ["bash", str(SETUP_SCRIPT), "--with-wpe"], check=False
                )
                if result.returncode == 0:
                    print(f"\n{Fore.GREEN}✓ Setup completed successfully!{Style.RESET_ALL}\n")
                else:
                    print(f"\n{Fore.YELLOW}⚠ Setup completed with warnings.{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}ERROR: Setup failed: {e}{Style.RESET_ALL}\n")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True

        elif setup_choice == '3':
            if TEST_SCRIPT.exists():
                print(f"\n{Fore.GREEN}Running system diagnostics...{Style.RESET_ALL}\n")
                try:
                    result = subprocess.run(
                        ["bash", str(TEST_SCRIPT), "--quick"], check=False
                    )
                    if result.returncode == 0:
                        print(f"\n{Fore.GREEN}✓ System check passed!{Style.RESET_ALL}\n")
                    else:
                        print(f"\n{Fore.YELLOW}⚠ Some checks failed.{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}ERROR: {e}{Style.RESET_ALL}\n")
            else:
                print(f"\n{Fore.YELLOW}Test script not found. Running basic checks...{Style.RESET_ALL}\n")
                run_basic_checks()
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True

        elif setup_choice == '4':
            print(f"\n{Fore.CYAN}Setup cancelled. Returning to menu...{Style.RESET_ALL}\n")
            return False
        else:
            print(f"{Fore.RED}Invalid option. Please select 1-4.{Style.RESET_ALL}")


def run_basic_checks():
    """Run basic system checks without full setup"""
    print(f"{Fore.CYAN}Running basic system checks...{Style.RESET_ALL}\n")

    required_commands = ['hostapd', 'dnsmasq', 'iptables', 'iw', 'ip']
    all_present = True

    print(f"{Fore.WHITE}Checking required commands:{Style.RESET_ALL}")
    for cmd in required_commands:
        path = shutil.which(cmd)
        if path:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {cmd}: {path}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {cmd}: NOT FOUND")
            all_present = False

    print(f"\n{Fore.WHITE}Checking optional commands:{Style.RESET_ALL}")
    optional_commands = ['hostapd-wpe', 'tcpdump', 'aircrack-ng', 'tshark']
    for cmd in optional_commands:
        path = shutil.which(cmd)
        if path:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {cmd}: {path}")
        else:
            print(f"  {Fore.YELLOW}-{Style.RESET_ALL} {cmd}: not installed (optional)")

    print(f"\n{Fore.WHITE}Checking wireless interfaces:{Style.RESET_ALL}")
    try:
        result = subprocess.run(
            ['iw', 'dev'], capture_output=True, text=True, check=False
        )
        if 'Interface' in result.stdout:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Wireless interface(s) detected")
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    print(f"    • {line.split()[-1]}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} No wireless interfaces found")
            all_present = False
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Error checking interfaces: {e}")
        all_present = False

    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    if all_present:
        print(f"{Fore.GREEN}✓ All required components are present!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}✗ Some required components are missing.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run full setup (option 1 or 2) to install them.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")


def get_wireless_interfaces():
    """Get available wireless interfaces"""
    try:
        result = subprocess.run(
            ['iw', 'dev'], capture_output=True, text=True, check=False
        )
        return [
            line.split()[-1]
            for line in result.stdout.split('\n')
            if 'Interface' in line
        ]
    except Exception:
        return []


def _pick_interface(prompt="Enter interface"):
    """Helper — show interfaces and prompt for selection"""
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print(f"{Fore.RED}No wireless interfaces found!{Style.RESET_ALL}")
        input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
        return None
    print(f"{Fore.WHITE}Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
    iface = input(
        f"{Fore.YELLOW}{prompt} (default: {interfaces[0]}): {Style.RESET_ALL}"
    ).strip()
    return iface if iface else interfaces[0]


def _run_script(cmd):
    """Run a subprocess command, handling KeyboardInterrupt cleanly"""
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted by user.{Style.RESET_ALL}")


# FIX 1: get_script_path returns direct path — no copy
def get_script_path(script_type):
    """Return the direct path to the script, verifying it exists"""
    source = LOCAL_SCRIPTS[script_type]
    if not source.exists():
        print(f"{Fore.RED}ERROR: Script not found at {source}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Make sure all files are properly installed.{Style.RESET_ALL}")
        return None
    # Ensure it's executable
    source.chmod(0o755)
    return str(source)


def show_authorization_warning(script_type):
    """Show authorization warning for offensive tools"""
    # FIX 3: defender doesn't need auth warning — only offensive tools do
    if script_type not in ['basic', 'advanced']:
        return True

    print(f"\n{Fore.RED}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.RED}            ⚠️  AUTHORIZATION REQUIRED  ⚠️{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*65}{Style.RESET_ALL}\n")

    print(f"{Fore.YELLOW}You are about to launch an OFFENSIVE security tool.{Style.RESET_ALL}\n")
    print(f"{Fore.WHITE}Before proceeding, you MUST have:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ✓ {Fore.WHITE}Written authorization from the network owner")
    print(f"{Fore.CYAN}  ✓ {Fore.WHITE}Clearly defined scope of testing")
    print(f"{Fore.CYAN}  ✓ {Fore.WHITE}Legal approval for password capture")
    print(f"{Fore.CYAN}  ✓ {Fore.WHITE}Understanding of applicable laws\n")

    print(f"{Fore.RED}WITHOUT PROPER AUTHORIZATION, YOU MAY BE COMMITTING A CRIME.{Style.RESET_ALL}\n")
    print(f"{Fore.RED}{'='*65}{Style.RESET_ALL}\n")

    while True:
        confirm = input(
            f"{Fore.YELLOW}Type 'I HAVE AUTHORIZATION' to proceed: {Style.RESET_ALL}"
        ).strip()

        if confirm == "I HAVE AUTHORIZATION":
            print(f"\n{Fore.GREEN}✓ Authorization confirmed. Proceeding...{Style.RESET_ALL}\n")
            return True
        else:
            print(f"\n{Fore.RED}Authorization not confirmed.{Style.RESET_ALL}")
            retry = input(
                f"{Fore.YELLOW}Return to main menu? (yes/no): {Style.RESET_ALL}"
            ).strip().lower()
            if retry in ['yes', 'y']:
                return False
            elif retry in ['no', 'n']:
                print(f"\n{Fore.CYAN}Exiting...{Style.RESET_ALL}\n")
                sys.exit(0)


def launch_script(script_path, script_type):
    """Launch the selected script with user-provided arguments"""
    print(f"{Fore.CYAN}Preparing {SCRIPT_NAMES[script_type]}...{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}")

    if script_type == 'basic':
        print(f"{Fore.WHITE}The script will prompt you for:")
        print(f"  • SSID (network name)")
        print(f"  • Channel (1-14)")
        print(f"  • Uplink interface (e.g. eth0 or 'none')")
        print(f"  • Whether to enable password capture")
        print(f"\n{Fore.WHITE}Or pass arguments directly:")
        print(f'{Fore.CYAN}  Example: "TestAP" 6 eth0 --capture-auth{Style.RESET_ALL}')
        print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}\n")

        # FIX 5: Collect optional args from user before launching
        args_input = input(
            f"{Fore.YELLOW}Arguments (or press ENTER to use interactive mode): {Style.RESET_ALL}"
        ).strip()
        print()
        # FIX 4: use shlex.split for safe argument parsing
        extra_args = shlex.split(args_input) if args_input else []
        _run_script(["bash", script_path] + extra_args)

    elif script_type == 'advanced':
        print(f"{Fore.WHITE}The script will prompt you for:")
        print(f"  • SSID, channel, uplink interface")
        print(f"  • Optional features (monitoring, captive portal, etc.)")
        print(f"\n{Fore.WHITE}Or pass arguments directly:")
        print(f'{Fore.CYAN}  Example: "TestAP" 6 eth0 --capture-auth --monitor{Style.RESET_ALL}')
        print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}\n")

        # FIX 5: Collect optional args from user before launching
        args_input = input(
            f"{Fore.YELLOW}Arguments (or press ENTER to use interactive mode): {Style.RESET_ALL}"
        ).strip()
        print()
        # FIX 4: use shlex.split for safe argument parsing
        extra_args = shlex.split(args_input) if args_input else []
        _run_script(["bash", script_path] + extra_args)

    elif script_type == 'defender':
        _launch_defender_menu(script_path)
        return True

    print(f"\n{Fore.CYAN}Script finished. Returning to main menu...{Style.RESET_ALL}")
    input(f"{Fore.GREEN}Press ENTER to continue...{Style.RESET_ALL}")
    return True


def _launch_defender_menu(script_path):
    """Defender sub-menu"""
    while True:
        clear()
        print(f"\n{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║                    MAIN DEFENDER MENU                          ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        print(f"{Fore.GREEN}▶ SCANNING & MONITORING{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [1]{Fore.WHITE} Quick Scan")
        print(f"{Fore.CYAN}  [2]{Fore.WHITE} Monitor Mode — continuous real-time monitoring")
        print(f"{Fore.CYAN}  [3]{Fore.WHITE} Advanced Monitor — deep packet inspection & analysis")
        print(f"{Fore.CYAN}  [4]{Fore.WHITE} Baseline Creation")

        print(f"\n{Fore.GREEN}▶ THREAT ANALYSIS & REPORTING{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [5]{Fore.WHITE} Threat Dashboard")
        print(f"{Fore.CYAN}  [6]{Fore.WHITE} Security Report")
        print(f"{Fore.CYAN}  [7]{Fore.WHITE} Analyze Log File")
        print(f"{Fore.CYAN}  [8]{Fore.WHITE} Client Tracking")

        print(f"\n{Fore.GREEN}▶ PROTECTION & MANAGEMENT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [9]{Fore.WHITE} Protect Network")
        print(f"{Fore.CYAN} [10]{Fore.WHITE} Whitelist Manager")
        print(f"{Fore.CYAN} [11]{Fore.WHITE} Blacklist Manager")

        print(f"\n{Fore.GREEN}▶ ADVANCED OPTIONS{Style.RESET_ALL}")
        print(f"{Fore.CYAN} [12]{Fore.WHITE} Alert Configuration")
        print(f"{Fore.CYAN} [13]{Fore.WHITE} Detection Settings")
        # FIX 4: Custom command now uses shlex.split — shown in option 14
        print(f"{Fore.CYAN} [14]{Fore.WHITE} Custom Command")

        print(f"\n{Fore.GREEN}▶ SYSTEM{Style.RESET_ALL}")
        print(f"{Fore.CYAN} [15]{Fore.WHITE} Help")
        print(f"{Fore.CYAN} [16]{Fore.WHITE} View Logs")
        print(f"{Fore.CYAN} [17]{Fore.WHITE} Back to Main Menu")
        print(f"{Fore.YELLOW}{'='*75}{Style.RESET_ALL}\n")

        choice = input(f"{Fore.YELLOW}Select option [1-17]: {Style.RESET_ALL}").strip()

        if choice == '1':
            iface = _pick_interface()
            if not iface:
                continue
            print(f"\n{Fore.GREEN}Starting quick scan on {iface}...{Style.RESET_ALL}\n")
            _run_script(["bash", script_path, "--scan", iface])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '2':
            iface = _pick_interface()
            if not iface:
                continue
            interval = input(
                f"{Fore.YELLOW}Scan interval in seconds (default: 10): {Style.RESET_ALL}"
            ).strip() or "10"
            print(f"\n{Fore.GREEN}Monitoring on {iface} every {interval}s...{Style.RESET_ALL}")
            print(f"{Fore.RED}Press CTRL+C to stop{Style.RESET_ALL}\n")
            _run_script(["bash", script_path, "--monitor", iface, interval])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '3':
            iface = _pick_interface()
            if not iface:
                continue

            print(f"\n{Fore.YELLOW}Select advanced features:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  [1]{Fore.WHITE} All features (recommended)")
            print(f"{Fore.CYAN}  [2]{Fore.WHITE} Deep packet inspection only")
            print(f"{Fore.CYAN}  [3]{Fore.WHITE} DNS & ARP monitoring")
            print(f"{Fore.CYAN}  [4]{Fore.WHITE} Client fingerprinting & probe tracking")
            print(f"{Fore.CYAN}  [5]{Fore.WHITE} Custom selection")

            feature_choice = input(f"{Fore.YELLOW}Select [1-5]: {Style.RESET_ALL}").strip()
            cmd = ["bash", script_path, "--monitor", iface]

            if feature_choice == '1':
                cmd += ["--deep-inspection", "--capture-packets",
                        "--analyze-dns", "--analyze-arp",
                        "--track-probes", "--fingerprint-clients"]
            elif feature_choice == '2':
                cmd += ["--deep-inspection", "--capture-packets"]
            elif feature_choice == '3':
                cmd += ["--analyze-dns", "--analyze-arp"]
            elif feature_choice == '4':
                cmd += ["--track-probes", "--fingerprint-clients"]
            elif feature_choice == '5':
                print(f"\n{Fore.YELLOW}Enable features (y/n):{Style.RESET_ALL}")
                if input("  Deep packet inspection? ").lower() == 'y':
                    cmd.append("--deep-inspection")
                if input("  Capture packets? ").lower() == 'y':
                    cmd.append("--capture-packets")
                if input("  DNS monitoring? ").lower() == 'y':
                    cmd.append("--analyze-dns")
                if input("  ARP monitoring? ").lower() == 'y':
                    cmd.append("--analyze-arp")
                if input("  Track probe requests? ").lower() == 'y':
                    cmd.append("--track-probes")
                if input("  Fingerprint clients? ").lower() == 'y':
                    cmd.append("--fingerprint-clients")

            print(f"\n{Fore.GREEN}Starting advanced monitoring...{Style.RESET_ALL}")
            print(f"{Fore.RED}Press CTRL+C to stop{Style.RESET_ALL}\n")
            _run_script(cmd)
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '4':
            iface = _pick_interface()
            if not iface:
                continue
            print(f"\n{Fore.GREEN}Creating baseline on {iface}...{Style.RESET_ALL}\n")
            _run_script(["bash", script_path, "--baseline", iface])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '5':
            _run_script(["bash", script_path, "--threats"])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '6':
            _run_script(["bash", script_path, "--report"])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '7':
            log_dir = "/tmp/fake_ap_detector"
            print(f"\n{Fore.YELLOW}Common log locations:{Style.RESET_ALL}")
            print(f"  • {log_dir}/scan_results.log")
            print(f"  • {log_dir}/monitor.log")
            print(f"  • {log_dir}/alerts.log\n")
            log_file = input(f"{Fore.YELLOW}Enter log file path: {Style.RESET_ALL}").strip()
            if log_file and os.path.exists(log_file):
                _run_script(["bash", script_path, "--analyze", log_file])
            else:
                print(f"{Fore.RED}File not found: {log_file}{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '8':
            _run_script(["bash", script_path, "--clients"])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '9':
            ssid  = input(f"{Fore.YELLOW}Enter network SSID: {Style.RESET_ALL}").strip()
            bssid = input(f"{Fore.YELLOW}Enter AP BSSID: {Style.RESET_ALL}").strip()
            if ssid and bssid:
                _run_script(["bash", script_path, "--protect", ssid, bssid])
            else:
                print(f"{Fore.RED}Both SSID and BSSID are required.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '10':
            _whitelist_manager(script_path)

        elif choice == '11':
            _blacklist_manager(script_path)

        elif choice == '12':
            _alert_config()

        elif choice == '13':
            print(f"\n{Fore.CYAN}Detection settings are configured via command-line flags.{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Use option [3] Advanced Monitor to enable specific features.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '14':
            # FIX 4: Use shlex.split instead of naive str.split()
            # This handles quoted args like --protect "My Network" correctly
            print(f"\n{Fore.WHITE}Enter custom arguments for fake_ap_detector.sh{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Examples:{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}--scan wlan0{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}--monitor wlan0 --deep-inspection --analyze-dns{Style.RESET_ALL}")
            print(f'  {Fore.CYAN}--protect "My Network" "AA:BB:CC:DD:EE:FF"{Style.RESET_ALL}')
            args_str = input(f"\n{Fore.YELLOW}Arguments: {Style.RESET_ALL}").strip()
            if args_str:
                try:
                    args = shlex.split(args_str)
                    _run_script(["bash", script_path] + args)
                except ValueError as e:
                    print(f"{Fore.RED}Argument parse error: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}No arguments provided.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '15':
            _run_script(["bash", script_path, "--help"])
            input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

        elif choice == '16':
            _view_logs()

        elif choice == '17':
            return True
        else:
            print(f"{Fore.RED}Invalid option. Please select 1-17.{Style.RESET_ALL}")


def _whitelist_manager(script_path):
    """Manage trusted AP whitelist"""
    whitelist_file = "/tmp/fake_ap_detector/whitelist.txt"
    print(f"\n{Fore.CYAN}╔═══════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║       WHITELIST MANAGER           ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════╝{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}  [1]{Fore.WHITE} Add BSSID")
    print(f"{Fore.CYAN}  [2]{Fore.WHITE} View whitelist")
    print(f"{Fore.CYAN}  [3]{Fore.WHITE} Remove entry")
    print(f"{Fore.CYAN}  [4]{Fore.WHITE} Back\n")

    wl_choice = input(f"{Fore.YELLOW}Select [1-4]: {Style.RESET_ALL}").strip()

    if wl_choice == '1':
        bssid = input(f"{Fore.YELLOW}Enter BSSID: {Style.RESET_ALL}").strip()
        if bssid:
            _run_script(["bash", script_path, "--whitelist", bssid])
    elif wl_choice == '2':
        if os.path.exists(whitelist_file):
            print(f"\n{Fore.GREEN}Current whitelist:{Style.RESET_ALL}\n")
            with open(whitelist_file, 'r') as f:
                entries = [l.strip() for l in f if l.strip()]
            if entries:
                for e in entries:
                    print(f"  • {e}")
            else:
                print(f"  {Fore.YELLOW}(empty){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Whitelist file not found.{Style.RESET_ALL}")
    elif wl_choice == '3':
        if os.path.exists(whitelist_file):
            bssid = input(f"{Fore.YELLOW}Enter BSSID to remove: {Style.RESET_ALL}").strip()
            if bssid:
                with open(whitelist_file, 'r') as f:
                    lines = f.readlines()
                with open(whitelist_file, 'w') as f:
                    removed = 0
                    for line in lines:
                        if line.strip() != bssid:
                            f.write(line)
                        else:
                            removed += 1
                print(
                    f"{Fore.GREEN}Removed {removed} entry(s).{Style.RESET_ALL}"
                    if removed else
                    f"{Fore.YELLOW}{bssid} not found in whitelist.{Style.RESET_ALL}"
                )
        else:
            print(f"{Fore.YELLOW}Whitelist file not found.{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")


def _blacklist_manager(script_path):
    """Manage known rogue AP blacklist"""
    blacklist_file = "/tmp/fake_ap_detector/blacklist.txt"
    print(f"\n{Fore.CYAN}╔═══════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║       BLACKLIST MANAGER           ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════╝{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}  [1]{Fore.WHITE} Add BSSID")
    print(f"{Fore.CYAN}  [2]{Fore.WHITE} View blacklist")
    print(f"{Fore.CYAN}  [3]{Fore.WHITE} Remove entry")
    print(f"{Fore.CYAN}  [4]{Fore.WHITE} Back\n")

    bl_choice = input(f"{Fore.YELLOW}Select [1-4]: {Style.RESET_ALL}").strip()

    if bl_choice == '1':
        bssid = input(f"{Fore.YELLOW}Enter BSSID: {Style.RESET_ALL}").strip()
        if bssid:
            _run_script(["bash", script_path, "--blacklist", bssid])
    elif bl_choice == '2':
        if os.path.exists(blacklist_file):
            print(f"\n{Fore.RED}Current blacklist:{Style.RESET_ALL}\n")
            with open(blacklist_file, 'r') as f:
                entries = [l.strip() for l in f if l.strip()]
            if entries:
                for e in entries:
                    print(f"  • {e}")
            else:
                print(f"  {Fore.YELLOW}(empty){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Blacklist file not found.{Style.RESET_ALL}")
    elif bl_choice == '3':
        if os.path.exists(blacklist_file):
            bssid = input(f"{Fore.YELLOW}Enter BSSID to remove: {Style.RESET_ALL}").strip()
            if bssid:
                with open(blacklist_file, 'r') as f:
                    lines = f.readlines()
                with open(blacklist_file, 'w') as f:
                    removed = 0
                    for line in lines:
                        if line.strip() != bssid:
                            f.write(line)
                        else:
                            removed += 1
                print(
                    f"{Fore.GREEN}Removed {removed} entry(s).{Style.RESET_ALL}"
                    if removed else
                    f"{Fore.YELLOW}{bssid} not found in blacklist.{Style.RESET_ALL}"
                )
        else:
            print(f"{Fore.YELLOW}Blacklist file not found.{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")


def _alert_config():
    """Show alert configuration info"""
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║       ALERT CONFIGURATION            ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════╝{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}Add these flags to the monitoring command (option 2 or 3):{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}  Email:     {Fore.WHITE}--alert-email user@example.com")
    print(f"{Fore.CYAN}  Webhook:   {Fore.WHITE}--alert-webhook https://your-webhook.url")
    print(f"{Fore.CYAN}  Slack:     {Fore.WHITE}--alert-slack https://hooks.slack.com/...")
    print(f"{Fore.CYAN}  Telegram:  {Fore.WHITE}--alert-telegram BOT_TOKEN CHAT_ID")
    print(f"{Fore.CYAN}  Sound:     {Fore.WHITE}--sound-alert")
    print(f"{Fore.CYAN}  No notify: {Fore.WHITE}--no-notify\n")
    print(f"{Fore.WHITE}Or use option [14] Custom Command to pass flags directly.{Style.RESET_ALL}")
    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")


def _view_logs():
    """Quick log file viewer"""
    log_dir = "/tmp/fake_ap_detector"
    log_files = {
        '1': ('scan_results.log',   'Scan Results'),
        '2': ('monitor.log',        'Monitor Log'),
        '3': ('alerts.log',         'Security Alerts'),
        '4': ('rogue_aps.db',       'Rogue APs Database'),
        '5': ('threat_scores.log',  'Threat Scores'),
        '6': ('deauth_attacks.log', 'Deauth Attacks'),
        '7': ('client_tracking.db', 'Client Tracking'),
        '8': ('dns_spoofing.log',   'DNS Spoofing'),
        '9': ('arp_spoofing.log',   'ARP Spoofing'),
    }

    print(f"\n{Fore.YELLOW}Available log files:{Style.RESET_ALL}\n")
    for key, (filename, description) in log_files.items():
        filepath = os.path.join(log_dir, filename)
        exists = "✓" if os.path.exists(filepath) else "✗"
        color = Fore.GREEN if exists == "✓" else Fore.RED
        print(f"{Fore.CYAN}  [{key}]{Style.RESET_ALL} {color}{exists}{Style.RESET_ALL} "
              f"{description} ({filename})")
    print(f"{Fore.CYAN}  [0]{Style.RESET_ALL} Back\n")

    log_choice = input(f"{Fore.YELLOW}Select log [0-9]: {Style.RESET_ALL}").strip()

    if log_choice in log_files:
        filename, description = log_files[log_choice]
        filepath = os.path.join(log_dir, filename)
        if os.path.exists(filepath):
            print(f"\n{Fore.GREEN}=== {description} ==={Style.RESET_ALL}\n")
            try:
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                if len(lines) > 50:
                    print(f"{Fore.YELLOW}Showing last 50 lines:{Style.RESET_ALL}\n")
                    lines = lines[-50:]
                for line in lines:
                    print(line.rstrip())
            except Exception as e:
                print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Log file not found: {filepath}{Style.RESET_ALL}")

    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")


def main():
    """Main program flow"""
    try:
        check_root()

        # FIX 6: sleep(1) only here — on first launch, not on every menu redraw
        print_logo()
        sleep(1)

        # FIX 2: show_disclaimer no longer returns a value — just returns or exits
        show_disclaimer()

        # FIX 8: show_guide only on first launch, not every run
        # Check a marker file to detect first run
        first_run_marker = Path.home() / ".robowifi" / ".guide_shown"
        if not first_run_marker.exists():
            show_guide()
            first_run_marker.parent.mkdir(parents=True, exist_ok=True)
            first_run_marker.touch()

        while True:
            choice = show_main_menu()

            if choice == 'setup':
                run_setup()
                continue

            # Show authorization warning for offensive tools
            if not show_authorization_warning(choice):
                continue

            # FIX 1: Get direct script path — no copying
            script_path = get_script_path(choice)

            if script_path:
                launch_script(script_path, choice)
            else:
                print(f"\n{Fore.RED}Failed to find script.{Style.RESET_ALL}")
                retry = input(
                    f"{Fore.YELLOW}Return to main menu? (yes/no): {Style.RESET_ALL}"
                ).strip().lower()
                if retry not in ['yes', 'y']:
                    sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}CRITICAL ERROR: {str(e)}{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()