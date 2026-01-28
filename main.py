#!/usr/bin/env python3
"""
RoboWiFi-AP - WiFi Security Assessment Framework
A tool for authorized penetration testing and security research
"""

import os
import sys
import shutil
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
    
    guide_text = f"""{Fore.WHITE}RoboWiFi-AP provides three operational modes:

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
        
        menu_text = f"""{Fore.GREEN}[1]{Fore.WHITE} Basic Fake Access Point
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
        
        choice = input(f"{Fore.YELLOW}Select an option [1-4]: {Style.RESET_ALL}").strip()
        
        if choice == '1':
            return 'basic'
        elif choice == '2':
            return 'advanced'
        elif choice == '3':
            return 'defender'
        elif choice == '4':
            print(f"\n{Fore.CYAN}Exiting... Stay safe!{Style.RESET_ALL}\n")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}Invalid option. Please select 1-4.{Style.RESET_ALL}")
            input(f"{Fore.CYAN}Press ENTER to continue...{Style.RESET_ALL}")

def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        print(f"\n{Fore.RED}ERROR: This tool requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please run with: sudo python3 {sys.argv[0]}{Style.RESET_ALL}\n")
        sys.exit(1)

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
    elif script_type == 'advanced':
        print(f"{Fore.WHITE}TIP: Advanced usage example:")
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0 --capture-auth --monitor{Style.RESET_ALL}')
        print(f'{Fore.CYAN}  sudo {script_path} "TestAP" 6 eth0 --captive-portal{Style.RESET_ALL}')
    elif script_type == 'defender':
        print(f"{Fore.WHITE}TIP: Defender usage example:")
        print(f'{Fore.CYAN}  sudo {script_path} --scan{Style.RESET_ALL}')
        print(f'{Fore.CYAN}  sudo {script_path} --monitor wlan0{Style.RESET_ALL}')
    
    print(f"{Fore.YELLOW}{'='*65}{Style.RESET_ALL}\n")
    
    input(f"{Fore.GREEN}Press ENTER to launch the script...{Style.RESET_ALL}")
    
    # Execute the script
    print()
    os.execvp("bash", ["bash", script_path])

def main():
    """Main program flow"""
    try:
        # Check root privileges
        check_root()
        
        # Show disclaimer and get acceptance
        if not show_disclaimer():
            sys.exit(0)
        
        # Show tool guide
        show_guide()
        
        # Main loop
        while True:
            # Show main menu and get choice
            choice = show_main_menu()
            
            # Show authorization warning for offensive tools
            if not show_authorization_warning(choice):
                continue
            
            # Copy and prepare the script
            script_path = copy_script(choice)
            
            if script_path:
                # Launch the script
                launch_script(script_path, choice)
                break  # This line won't be reached due to exec, but included for clarity
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