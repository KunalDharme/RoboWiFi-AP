#!/usr/bin/env python3
"""
RoboWiFi-AP - WiFi Security Assessment Framework
A tool for authorized penetration testing and security research
"""

import os
import sys
import shutil
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
SCRIPTS_DIR = Path.home() / ".robowifi"
SCRIPT_DIR = Path(__file__).parent

# Local script paths
LOCAL_SCRIPTS = {
    "basic": SCRIPT_DIR / "scripts" / "fake_ap.sh",
    "advanced": SCRIPT_DIR / "scripts" / "advanced_fake_ap.sh",
    "defender": SCRIPT_DIR / "scripts" / "fake_ap_detector.sh"
}

SCRIPT_NAMES = {
    "basic": "fake_ap.sh",
    "advanced": "advanced_fake_ap.sh",
    "defender": "fake_ap_detector.sh"
}

# Setup script path
SETUP_SCRIPT = SCRIPT_DIR / "setup.sh"
TEST_SCRIPT = SCRIPT_DIR / "test.sh"

def clear():
    """Clear the terminal screen"""
    os.system("clear" if os.name == "posix" else "cls")

def print_logo():
    """Minimal banner - shown only once"""
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
    sleep(1) 

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
        response = input(f"{Fore.YELLOW}Do you accept these terms? (yes/no): {Style.RESET_ALL}").strip().lower()
        
        if response in ['yes', 'y']:
            print(f"\n{Fore.GREEN}✓ Terms accepted. Proceeding...{Style.RESET_ALL}\n")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True
        elif response in ['no', 'n']:
            print(f"\n{Fore.RED}Terms not accepted. Exiting...{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid input. Please type 'yes' or 'no'.{Style.RESET_ALL}")

def show_guide():
    """Display tool guide and information"""
    clear()
    print_logo()
    
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
        clear()
        print_logo()
        
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
    print_logo()
    
    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}              SETUP & REQUIREMENTS CHECK{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}This will:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  • Install required packages (hostapd, dnsmasq, etc.)")
    print(f"{Fore.CYAN}  • Check wireless adapter compatibility")
    print(f"{Fore.CYAN}  • Configure system settings")
    print(f"{Fore.CYAN}  • Optionally install hostapd-wpe for password capture")
    print(f"{Fore.CYAN}  • Run system diagnostics\n")
    
    # Check if setup script exists
    if not SETUP_SCRIPT.exists():
        print(f"{Fore.RED}ERROR: Setup script not found at {SETUP_SCRIPT}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please ensure setup.sh is in the same directory as this script.{Style.RESET_ALL}\n")
        input(f"{Fore.CYAN}Press ENTER to return to menu...{Style.RESET_ALL}")
        return False
    
    # Ask for confirmation
    print(f"{Fore.YELLOW}Setup Options:{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[1] Full setup (install all dependencies)")
    print(f"{Fore.WHITE}[2] Full setup + hostapd-wpe (for password capture)")
    print(f"{Fore.WHITE}[3] Quick check only (verify system without installing)")
    print(f"{Fore.WHITE}[4] Cancel and return to menu\n")
    
    while True:
        setup_choice = input(f"{Fore.YELLOW}Select setup option [1-4]: {Style.RESET_ALL}").strip()
        
        if setup_choice == '1':
            # Run full setup
            print(f"\n{Fore.GREEN}Starting full setup...{Style.RESET_ALL}\n")
            try:
                result = subprocess.run(
                    ["bash", str(SETUP_SCRIPT)],
                    check=False
                )
                if result.returncode == 0:
                    print(f"\n{Fore.GREEN}✓ Setup completed successfully!{Style.RESET_ALL}\n")
                else:
                    print(f"\n{Fore.YELLOW}⚠ Setup completed with warnings. Check output above.{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}ERROR: Setup failed: {e}{Style.RESET_ALL}\n")
            
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True
            
        elif setup_choice == '2':
            # Run full setup with hostapd-wpe
            print(f"\n{Fore.GREEN}Starting full setup with hostapd-wpe...{Style.RESET_ALL}\n")
            try:
                result = subprocess.run(
                    ["bash", str(SETUP_SCRIPT), "--with-wpe"],
                    check=False
                )
                if result.returncode == 0:
                    print(f"\n{Fore.GREEN}✓ Setup completed successfully!{Style.RESET_ALL}\n")
                else:
                    print(f"\n{Fore.YELLOW}⚠ Setup completed with warnings. Check output above.{Style.RESET_ALL}\n")
            except Exception as e:
                print(f"\n{Fore.RED}ERROR: Setup failed: {e}{Style.RESET_ALL}\n")
            
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
            return True
            
        elif setup_choice == '3':
            # Run quick check using test script
            if TEST_SCRIPT.exists():
                print(f"\n{Fore.GREEN}Running system diagnostics...{Style.RESET_ALL}\n")
                try:
                    result = subprocess.run(
                        ["bash", str(TEST_SCRIPT), "--quick"],
                        check=False
                    )
                    if result.returncode == 0:
                        print(f"\n{Fore.GREEN}✓ System check passed!{Style.RESET_ALL}\n")
                    else:
                        print(f"\n{Fore.YELLOW}⚠ Some checks failed. See output above.{Style.RESET_ALL}\n")
                except Exception as e:
                    print(f"\n{Fore.RED}ERROR: System check failed: {e}{Style.RESET_ALL}\n")
            else:
                print(f"\n{Fore.YELLOW}Test script not found. Running basic checks...{Style.RESET_ALL}\n")
                # Run basic checks
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
    
    # Check for required commands
    required_commands = ['hostapd', 'dnsmasq', 'iptables', 'iw', 'ip']
    all_present = True
    
    print(f"{Fore.WHITE}Checking required commands:{Style.RESET_ALL}")
    for cmd in required_commands:
        if shutil.which(cmd):
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {cmd}: {shutil.which(cmd)}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {cmd}: NOT FOUND")
            all_present = False
    
    # Check for optional commands
    print(f"\n{Fore.WHITE}Checking optional commands:{Style.RESET_ALL}")
    optional_commands = ['hostapd-wpe', 'tcpdump', 'aircrack-ng']
    for cmd in optional_commands:
        if shutil.which(cmd):
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {cmd}: {shutil.which(cmd)}")
        else:
            print(f"  {Fore.YELLOW}-{Style.RESET_ALL} {cmd}: not installed (optional)")
    
    # Check for wireless interfaces
    print(f"\n{Fore.WHITE}Checking wireless interfaces:{Style.RESET_ALL}")
    try:
        result = subprocess.run(
            ['iw', 'dev'],
            capture_output=True,
            text=True,
            check=False
        )
        if 'Interface' in result.stdout:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} Wireless interface(s) detected")
            # Show interface names
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    iface = line.split()[-1]
                    print(f"    • {iface}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} No wireless interfaces found")
            all_present = False
    except Exception as e:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} Error checking interfaces: {e}")
        all_present = False
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    if all_present:
        print(f"{Fore.GREEN}✓ All required components are present!{Style.RESET_ALL}")
        print(f"{Fore.WHITE}You can proceed to use the tools.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}✗ Some required components are missing.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Run full setup (option 1 or 2) to install them.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

def copy_script(script_type):
    """Copy the selected script to user's directory"""
    print(f"\n{Fore.CYAN}Preparing {SCRIPT_NAMES[script_type]}...{Style.RESET_ALL}")
    
    # Create directory if it doesn't exist
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    
    try:
        source_script = LOCAL_SCRIPTS[script_type]
        
        if not source_script.exists():
            print(f"{Fore.RED}ERROR: Script not found at {source_script}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Make sure all files are properly installed.{Style.RESET_ALL}")
            return None
        
        # Copy the script
        dest_path = SCRIPTS_DIR / SCRIPT_NAMES[script_type]
        shutil.copy2(source_script, dest_path)
        dest_path.chmod(0o755)  # Make executable
        
        print(f"{Fore.GREEN}✓ Script ready: {dest_path}{Style.RESET_ALL}\n")
        return str(dest_path)
        
    except Exception as e:
        print(f"{Fore.RED}ERROR: Failed to prepare script{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Details: {str(e)}{Style.RESET_ALL}")
        return None

def show_authorization_warning(script_type):
    """Show authorization warning for offensive tools"""
    if script_type in ['basic', 'advanced']:
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
            confirm = input(f"{Fore.YELLOW}Type 'I HAVE AUTHORIZATION' to proceed: {Style.RESET_ALL}").strip()
            
            if confirm == "I HAVE AUTHORIZATION":
                print(f"\n{Fore.GREEN}✓ Authorization confirmed. Proceeding...{Style.RESET_ALL}\n")
                return True
            else:
                print(f"\n{Fore.RED}Authorization not confirmed.{Style.RESET_ALL}")
                retry = input(f"{Fore.YELLOW}Return to main menu? (yes/no): {Style.RESET_ALL}").strip().lower()
                if retry in ['yes', 'y']:
                    return False
                elif retry in ['no', 'n']:
                    print(f"\n{Fore.CYAN}Exiting...{Style.RESET_ALL}\n")
                    sys.exit(0)
    return True

def launch_script(script_path, script_type):
    """Launch the selected script"""
    print(f"{Fore.CYAN}Launching {SCRIPT_NAMES[script_type]}...{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}")
    
    if script_type == 'basic':
        print(f"{Fore.WHITE}TIP: Basic usage example:")
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0{Style.RESET_ALL}')
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0 --capture-auth{Style.RESET_ALL}')
        print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}\n")
        input(f"{Fore.GREEN}Press ENTER to launch the script...{Style.RESET_ALL}")
        print()
        
        # Run script and return to menu after
        try:
            subprocess.run(["bash", script_path], check=False)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Script interrupted by user.{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Script finished. Returning to main menu...{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press ENTER to continue...{Style.RESET_ALL}")
        return True
        
    elif script_type == 'advanced':
        print(f"{Fore.WHITE}TIP: Advanced usage example:")
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0 --capture-auth --monitor{Style.RESET_ALL}')
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0 --captive-portal{Style.RESET_ALL}')
        print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}\n")
        input(f"{Fore.GREEN}Press ENTER to launch the script...{Style.RESET_ALL}")
        print()
        
        # Run script and return to menu after
        try:
            subprocess.run(["bash", script_path], check=False)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Script interrupted by user.{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Script finished. Returning to main menu...{Style.RESET_ALL}")
        input(f"{Fore.GREEN}Press ENTER to continue...{Style.RESET_ALL}")
        return True
        
    elif script_type == 'defender':
        print(f"{Fore.WHITE}Defender Mode - Rogue AP Detection & Defense System{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*75}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║                    MAIN DEFENDER MENU                          ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}▶ SCANNING & MONITORING{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [1]{Fore.WHITE} Quick Scan - Scan for rogue access points")
        print(f"{Fore.CYAN}  [2]{Fore.WHITE} Monitor Mode - Continuous real-time monitoring")
        print(f"{Fore.CYAN}  [3]{Fore.WHITE} Advanced Monitor - Deep packet inspection & analysis")
        print(f"{Fore.CYAN}  [4]{Fore.WHITE} Baseline Creation - Establish trusted AP baseline")
        
        print(f"\n{Fore.GREEN}▶ THREAT ANALYSIS & REPORTING{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [5]{Fore.WHITE} Threat Dashboard - View live threat scoring")
        print(f"{Fore.CYAN}  [6]{Fore.WHITE} Security Report - Generate comprehensive report")
        print(f"{Fore.CYAN}  [7]{Fore.WHITE} Analyze Log File - Forensic analysis of captured data")
        print(f"{Fore.CYAN}  [8]{Fore.WHITE} Client Tracking - View tracked client devices")
        
        print(f"\n{Fore.GREEN}▶ PROTECTION & MANAGEMENT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [9]{Fore.WHITE} Protect Network - Add AP to protection whitelist")
        print(f"{Fore.CYAN} [10]{Fore.WHITE} Whitelist Manager - Manage trusted APs")
        print(f"{Fore.CYAN} [11]{Fore.WHITE} Blacklist Manager - Manage known rogue APs")
        
        print(f"\n{Fore.GREEN}▶ ADVANCED OPTIONS{Style.RESET_ALL}")
        print(f"{Fore.CYAN} [12]{Fore.WHITE} Alert Configuration - Configure email/webhook/Telegram alerts")
        print(f"{Fore.CYAN} [13]{Fore.WHITE} Detection Settings - Adjust sensitivity and features")
        print(f"{Fore.CYAN} [14]{Fore.WHITE} Custom Command - Execute custom defender arguments")
        
        print(f"\n{Fore.GREEN}▶ SYSTEM{Style.RESET_ALL}")
        print(f"{Fore.CYAN} [15]{Fore.WHITE} Help - Display comprehensive help menu")
        print(f"{Fore.CYAN} [16]{Fore.WHITE} View Logs - Quick access to log files")
        print(f"{Fore.CYAN} [17]{Fore.WHITE} Back to Main Menu")
        print(f"{Fore.YELLOW}{'='*75}{Style.RESET_ALL}\n")
        
        while True:
            choice = input(f"{Fore.YELLOW}Select option [1-17]: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                # Quick scan
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              QUICK ROGUE AP SCAN                       ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                # Get wireless interface
                interfaces = get_wireless_interfaces()
                if not interfaces:
                    print(f"{Fore.RED}No wireless interfaces found!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                    continue
                
                print(f"{Fore.WHITE}Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
                iface = input(f"{Fore.YELLOW}Enter interface (default: {interfaces[0]}): {Style.RESET_ALL}").strip()
                if not iface:
                    iface = interfaces[0]
                
                print(f"\n{Fore.GREEN}Starting quick scan on {iface}...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}This will scan for:{Style.RESET_ALL}")
                print(f"  • Evil Twin APs (duplicate SSIDs)")
                print(f"  • Rogue Access Points")
                print(f"  • Signal anomalies")
                print(f"  • Captive portals")
                print(f"  • Encryption downgrades\n")
                
                try:
                    subprocess.run(["bash", script_path, "--scan", iface], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}Scan complete!{Style.RESET_ALL}")
                input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '2':
                # Basic monitor mode
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║           CONTINUOUS MONITORING MODE                   ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                interfaces = get_wireless_interfaces()
                if not interfaces:
                    print(f"{Fore.RED}No wireless interfaces found!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                    continue
                
                print(f"{Fore.WHITE}Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
                iface = input(f"{Fore.YELLOW}Enter interface (default: {interfaces[0]}): {Style.RESET_ALL}").strip()
                if not iface:
                    iface = interfaces[0]
                
                interval = input(f"{Fore.YELLOW}Scan interval in seconds (default: 10): {Style.RESET_ALL}").strip()
                if not interval:
                    interval = "10"
                
                print(f"\n{Fore.GREEN}Starting continuous monitoring on {iface} (interval: {interval}s)...{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Monitoring for:{Style.RESET_ALL}")
                print(f"  • Rogue APs")
                print(f"  • Deauth attacks")
                print(f"  • Evil twins")
                print(f"  • Signal anomalies")
                print(f"\n{Fore.RED}Press CTRL+C to stop monitoring{Style.RESET_ALL}\n")
                
                try:
                    subprocess.run(["bash", script_path, "--monitor", iface, interval], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Monitoring stopped by user.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '3':
                # Advanced monitor with deep inspection
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║        ADVANCED MONITORING WITH DEEP INSPECTION        ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                interfaces = get_wireless_interfaces()
                if not interfaces:
                    print(f"{Fore.RED}No wireless interfaces found!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                    continue
                
                print(f"{Fore.WHITE}Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
                iface = input(f"{Fore.YELLOW}Enter interface (default: {interfaces[0]}): {Style.RESET_ALL}").strip()
                if not iface:
                    iface = interfaces[0]
                
                print(f"\n{Fore.YELLOW}Select advanced features to enable:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}  [1]{Fore.WHITE} All features (recommended)")
                print(f"{Fore.CYAN}  [2]{Fore.WHITE} Deep packet inspection only")
                print(f"{Fore.CYAN}  [3]{Fore.WHITE} DNS & ARP monitoring")
                print(f"{Fore.CYAN}  [4]{Fore.WHITE} Client fingerprinting & probe tracking")
                print(f"{Fore.CYAN}  [5]{Fore.WHITE} Custom selection")
                
                feature_choice = input(f"{Fore.YELLOW}Select [1-5]: {Style.RESET_ALL}").strip()
                
                cmd = ["bash", script_path, "--monitor", iface]
                
                if feature_choice == '1':
                    cmd.extend([
                        "--deep-inspection",
                        "--capture-packets",
                        "--analyze-dns",
                        "--analyze-arp",
                        "--track-probes",
                        "--fingerprint-clients"
                    ])
                elif feature_choice == '2':
                    cmd.extend(["--deep-inspection", "--capture-packets"])
                elif feature_choice == '3':
                    cmd.extend(["--analyze-dns", "--analyze-arp"])
                elif feature_choice == '4':
                    cmd.extend(["--track-probes", "--fingerprint-clients"])
                elif feature_choice == '5':
                    print(f"\n{Fore.YELLOW}Enable features (y/n):{Style.RESET_ALL}")
                    if input(f"  Deep packet inspection? ").lower() == 'y':
                        cmd.append("--deep-inspection")
                    if input(f"  Capture packets? ").lower() == 'y':
                        cmd.append("--capture-packets")
                    if input(f"  DNS monitoring? ").lower() == 'y':
                        cmd.append("--analyze-dns")
                    if input(f"  ARP monitoring? ").lower() == 'y':
                        cmd.append("--analyze-arp")
                    if input(f"  Track probe requests? ").lower() == 'y':
                        cmd.append("--track-probes")
                    if input(f"  Fingerprint clients? ").lower() == 'y':
                        cmd.append("--fingerprint-clients")
                
                print(f"\n{Fore.GREEN}Starting advanced monitoring...{Style.RESET_ALL}")
                print(f"{Fore.RED}Press CTRL+C to stop{Style.RESET_ALL}\n")
                
                try:
                    subprocess.run(cmd, check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Monitoring stopped by user.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '4':
                # Create baseline
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              BASELINE CREATION                         ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}This will scan your network and create a baseline of{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}legitimate access points for future comparison.{Style.RESET_ALL}\n")
                
                interfaces = get_wireless_interfaces()
                if not interfaces:
                    print(f"{Fore.RED}No wireless interfaces found!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                    continue
                
                iface = input(f"{Fore.YELLOW}Enter interface (default: {interfaces[0]}): {Style.RESET_ALL}").strip()
                if not iface:
                    iface = interfaces[0]
                
                print(f"\n{Fore.GREEN}Creating baseline on {iface}...{Style.RESET_ALL}\n")
                
                try:
                    subprocess.run(["bash", script_path, "--baseline", iface], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Baseline creation interrupted.{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}Baseline created successfully!{Style.RESET_ALL}")
                input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '5':
                # Threat dashboard
                print(f"\n{Fore.GREEN}Launching threat dashboard...{Style.RESET_ALL}\n")
                try:
                    subprocess.run(["bash", script_path, "--threats"], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Dashboard closed.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '6':
                # Security report
                print(f"\n{Fore.GREEN}Generating comprehensive security report...{Style.RESET_ALL}\n")
                try:
                    subprocess.run(["bash", script_path, "--report"], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Report generation interrupted.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '7':
                # Analyze log file
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              LOG FILE ANALYSIS                         ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}Common log file locations:{Style.RESET_ALL}")
                print(f"  • /tmp/fake_ap_detector/scan_results.log")
                print(f"  • /tmp/fake_ap_detector/monitor.log")
                print(f"  • /tmp/fake_ap_detector/alerts.log\n")
                
                log_file = input(f"{Fore.YELLOW}Enter log file path: {Style.RESET_ALL}").strip()
                
                if log_file and os.path.exists(log_file):
                    print(f"\n{Fore.GREEN}Analyzing {log_file}...{Style.RESET_ALL}\n")
                    try:
                        subprocess.run(["bash", script_path, "--analyze", log_file], check=False)
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}Analysis interrupted.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}File not found or invalid path!{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '8':
                # Client tracking
                print(f"\n{Fore.GREEN}Displaying tracked clients...{Style.RESET_ALL}\n")
                try:
                    subprocess.run(["bash", script_path, "--clients"], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Client list closed.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '9':
                # Protect network
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║           NETWORK PROTECTION SETUP                     ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}This will protect a specific AP and alert on any clones.{Style.RESET_ALL}\n")
                
                ssid = input(f"{Fore.YELLOW}Enter network SSID: {Style.RESET_ALL}").strip()
                bssid = input(f"{Fore.YELLOW}Enter AP BSSID (MAC address): {Style.RESET_ALL}").strip()
                
                if ssid and bssid:
                    print(f"\n{Fore.GREEN}Adding {ssid} ({bssid}) to protection whitelist...{Style.RESET_ALL}\n")
                    try:
                        subprocess.run(["bash", script_path, "--protect", ssid, bssid], check=False)
                    except Exception as e:
                        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Both SSID and BSSID are required!{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '10':
                # Whitelist manager
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              WHITELIST MANAGER                         ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.CYAN}  [1]{Fore.WHITE} Add BSSID to whitelist")
                print(f"{Fore.CYAN}  [2]{Fore.WHITE} View current whitelist")
                print(f"{Fore.CYAN}  [3]{Fore.WHITE} Remove from whitelist")
                print(f"{Fore.CYAN}  [4]{Fore.WHITE} Back\n")
                
                wl_choice = input(f"{Fore.YELLOW}Select [1-4]: {Style.RESET_ALL}").strip()
                
                if wl_choice == '1':
                    bssid = input(f"{Fore.YELLOW}Enter BSSID to whitelist: {Style.RESET_ALL}").strip()
                    if bssid:
                        try:
                            subprocess.run(["bash", script_path, "--whitelist", bssid], check=False)
                        except Exception as e:
                            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                elif wl_choice == '2':
                    whitelist_file = "/tmp/fake_ap_detector/whitelist.txt"
                    if os.path.exists(whitelist_file):
                        print(f"\n{Fore.GREEN}Current whitelist:{Style.RESET_ALL}\n")
                        with open(whitelist_file, 'r') as f:
                            for line in f:
                                print(f"  • {line.strip()}")
                    else:
                        print(f"{Fore.YELLOW}Whitelist is empty{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                elif wl_choice == '3':
                    print(f"{Fore.YELLOW}Manual editing required: /tmp/fake_ap_detector/whitelist.txt{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '11':
                # Blacklist manager
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              BLACKLIST MANAGER                         ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.CYAN}  [1]{Fore.WHITE} Add BSSID to blacklist")
                print(f"{Fore.CYAN}  [2]{Fore.WHITE} View current blacklist")
                print(f"{Fore.CYAN}  [3]{Fore.WHITE} Remove from blacklist")
                print(f"{Fore.CYAN}  [4]{Fore.WHITE} Back\n")
                
                bl_choice = input(f"{Fore.YELLOW}Select [1-4]: {Style.RESET_ALL}").strip()
                
                if bl_choice == '1':
                    bssid = input(f"{Fore.YELLOW}Enter BSSID to blacklist: {Style.RESET_ALL}").strip()
                    if bssid:
                        try:
                            subprocess.run(["bash", script_path, "--blacklist", bssid], check=False)
                        except Exception as e:
                            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                elif bl_choice == '2':
                    blacklist_file = "/tmp/fake_ap_detector/blacklist.txt"
                    if os.path.exists(blacklist_file):
                        print(f"\n{Fore.RED}Current blacklist:{Style.RESET_ALL}\n")
                        with open(blacklist_file, 'r') as f:
                            for line in f:
                                print(f"  • {line.strip()}")
                    else:
                        print(f"{Fore.YELLOW}Blacklist is empty{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                elif bl_choice == '3':
                    print(f"{Fore.YELLOW}Manual editing required: /tmp/fake_ap_detector/blacklist.txt{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '12':
                # Alert configuration
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║           ALERT CONFIGURATION                          ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}Configure alert methods for monitoring mode:{Style.RESET_ALL}\n")
                print(f"{Fore.CYAN}  [1]{Fore.WHITE} Email alerts")
                print(f"{Fore.CYAN}  [2]{Fore.WHITE} Webhook alerts")
                print(f"{Fore.CYAN}  [3]{Fore.WHITE} Slack alerts")
                print(f"{Fore.CYAN}  [4]{Fore.WHITE} Telegram alerts")
                print(f"{Fore.CYAN}  [5]{Fore.WHITE} Sound alerts (toggle)")
                print(f"{Fore.CYAN}  [6]{Fore.WHITE} Desktop notifications (toggle)")
                print(f"{Fore.CYAN}  [7]{Fore.WHITE} Back\n")
                
                alert_choice = input(f"{Fore.YELLOW}Select [1-7]: {Style.RESET_ALL}").strip()
                
                if alert_choice == '1':
                    email = input(f"{Fore.YELLOW}Enter email address: {Style.RESET_ALL}").strip()
                    print(f"{Fore.GREEN}Email alerts configured: {email}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Use with: --alert-email {email}{Style.RESET_ALL}")
                elif alert_choice == '2':
                    webhook = input(f"{Fore.YELLOW}Enter webhook URL: {Style.RESET_ALL}").strip()
                    print(f"{Fore.GREEN}Webhook configured{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Use with: --alert-webhook {webhook}{Style.RESET_ALL}")
                elif alert_choice == '3':
                    slack = input(f"{Fore.YELLOW}Enter Slack webhook URL: {Style.RESET_ALL}").strip()
                    print(f"{Fore.GREEN}Slack alerts configured{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Use with: --alert-slack {slack}{Style.RESET_ALL}")
                elif alert_choice == '4':
                    token = input(f"{Fore.YELLOW}Enter Telegram bot token: {Style.RESET_ALL}").strip()
                    chat_id = input(f"{Fore.YELLOW}Enter Telegram chat ID: {Style.RESET_ALL}").strip()
                    print(f"{Fore.GREEN}Telegram alerts configured{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}Use with: --alert-telegram {token} {chat_id}{Style.RESET_ALL}")
                elif alert_choice in ['5', '6']:
                    flag = "--sound-alert" if alert_choice == '5' else "--no-notify"
                    print(f"{Fore.GREEN}Add {flag} to monitoring command{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '13':
                # Detection settings
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║           DETECTION SETTINGS                           ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.YELLOW}Available detection features:{Style.RESET_ALL}\n")
                print(f"{Fore.GREEN}✓ Evil Twin Detection{Style.RESET_ALL} - Detect duplicate SSIDs")
                print(f"{Fore.GREEN}✓ Rogue AP Detection{Style.RESET_ALL} - Identify unauthorized APs")
                print(f"{Fore.GREEN}✓ Deauth Attack Detection{Style.RESET_ALL} - Alert on deauth floods")
                print(f"{Fore.GREEN}✓ Signal Anomaly Detection{Style.RESET_ALL} - Detect suspicious signals")
                print(f"{Fore.GREEN}✓ Encryption Downgrade Alert{Style.RESET_ALL} - Warn when encryption weakens")
                print(f"{Fore.GREEN}✓ Channel Switching Detection{Style.RESET_ALL} - Track channel changes")
                print(f"{Fore.GREEN}✓ MAC Vendor Analysis{Style.RESET_ALL} - Identify suspicious manufacturers")
                print(f"{Fore.GREEN}✓ Captive Portal Detection{Style.RESET_ALL} - Detect fake login portals")
                print(f"{Fore.GREEN}✓ KARMA Attack Detection{Style.RESET_ALL} - Identify promiscuous APs")
                print(f"\n{Fore.CYAN}Advanced Features (enabled via flags):{Style.RESET_ALL}")
                print(f"  • DNS Spoofing Detection (--analyze-dns)")
                print(f"  • ARP Spoofing Detection (--analyze-arp)")
                print(f"  • Deep Packet Inspection (--deep-inspection)")
                print(f"  • Client Fingerprinting (--fingerprint-clients)")
                print(f"  • Probe Request Tracking (--track-probes)")
                print(f"  • Packet Capture (--capture-packets)")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '14':
                # Custom command
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              CUSTOM COMMAND EXECUTION                  ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                print(f"{Fore.WHITE}Enter custom arguments for fake_ap_detector.sh{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}Examples:{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}--scan wlan0{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}--monitor wlan0 --deep-inspection --analyze-dns{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}--protect \"MyNetwork\" \"AA:BB:CC:DD:EE:FF\"{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}--analyze /tmp/fake_ap_detector/scan_results.log{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}--monitor wlan0 --alert-email user@example.com --sound-alert{Style.RESET_ALL}")
                
                args = input(f"\n{Fore.YELLOW}Arguments: {Style.RESET_ALL}").strip()
                if args:
                    print(f"\n{Fore.GREEN}Launching with custom arguments...{Style.RESET_ALL}\n")
                    try:
                        subprocess.run(["bash", script_path] + args.split(), check=False)
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}Command interrupted by user.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}No arguments provided.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '15':
                # Show help
                print(f"\n{Fore.GREEN}Displaying comprehensive help menu...{Style.RESET_ALL}\n")
                try:
                    subprocess.run(["bash", script_path, "--help"], check=False)
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Help interrupted.{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '16':
                # View logs
                print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
                print(f"{Fore.CYAN}║              LOG FILE VIEWER                           ║{Style.RESET_ALL}")
                print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
                
                log_dir = "/tmp/fake_ap_detector"
                log_files = {
                    '1': ('scan_results.log', 'Scan Results'),
                    '2': ('monitor.log', 'Monitor Log'),
                    '3': ('alerts.log', 'Security Alerts'),
                    '4': ('rogue_aps.db', 'Rogue APs Database'),
                    '5': ('threat_scores.log', 'Threat Scores'),
                    '6': ('deauth_attacks.log', 'Deauth Attacks'),
                    '7': ('client_tracking.db', 'Client Tracking'),
                    '8': ('dns_spoofing.log', 'DNS Spoofing'),
                    '9': ('arp_spoofing.log', 'ARP Spoofing')
                }
                
                print(f"{Fore.YELLOW}Available log files:{Style.RESET_ALL}\n")
                for key, (filename, description) in log_files.items():
                    filepath = os.path.join(log_dir, filename)
                    exists = "✓" if os.path.exists(filepath) else "✗"
                    color = Fore.GREEN if exists == "✓" else Fore.RED
                    print(f"{Fore.CYAN}  [{key}]{Style.RESET_ALL} {color}{exists}{Style.RESET_ALL} {description} ({filename})")
                
                print(f"{Fore.CYAN}  [0]{Style.RESET_ALL} Back\n")
                
                log_choice = input(f"{Fore.YELLOW}Select log to view [0-9]: {Style.RESET_ALL}").strip()
                
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
                                    for line in lines[-50:]:
                                        print(line.rstrip())
                                else:
                                    for line in lines:
                                        print(line.rstrip())
                        except Exception as e:
                            print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Log file not found: {filepath}{Style.RESET_ALL}")
                
                input(f"\n{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")
                
            elif choice == '17':
                # Back to main menu
                print(f"\n{Fore.CYAN}Returning to main menu...{Style.RESET_ALL}")
                return True
                
            else:
                print(f"{Fore.RED}Invalid option. Please select 1-17.{Style.RESET_ALL}")


def get_wireless_interfaces():
    """Helper function to get available wireless interfaces"""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                iface = line.split()[-1]
                interfaces.append(iface)
        return interfaces
    except Exception:
        return []

def main():
    """Main program flow"""
    try:
        # Check root privileges
        check_root()
        
        # Show disclaimer and get acceptance (only once at start)
        if not show_disclaimer():
            sys.exit(0)
        
        # Show tool guide (only once at start)
        show_guide()
        
        # Main loop - keep running until user chooses exit
        while True:
            # Show main menu and get choice
            choice = show_main_menu()
            
            # Handle setup option
            if choice == 'setup':
                run_setup()
                continue  # Return to main menu after setup
            
            # Show authorization warning for offensive tools
            if not show_authorization_warning(choice):
                continue  # Return to menu if authorization denied
            
            # Copy and prepare the script
            script_path = copy_script(choice)
            
            if script_path:
                # Launch the script - it will return to menu when done
                launch_script(script_path, choice)
                # After script finishes, loop continues back to menu
            else:
                print(f"\n{Fore.RED}Failed to prepare script.{Style.RESET_ALL}")
                retry = input(f"{Fore.YELLOW}Return to main menu? (yes/no): {Style.RESET_ALL}").strip().lower()
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