import os
import sys
import time
import subprocess
import requests
from pathlib import Path
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

# Initialize
init(autoreset=True)
console = Console()

# Configuration
SCRIPTS_DIR = Path.home() / ".robowifi"
SCRIPT_URLS = {
    "red": "https://raw.githubusercontent.com/YOUR_REPO/fake_ap.sh",
    "blue": "https://raw.githubusercontent.com/YOUR_REPO/rogue_ap_detector.sh"
}
SCRIPT_NAMES = {
    "red": "fake_ap.sh",
    "blue": "rogue_ap_detector.sh"
}

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def matrix_type(text, delay=0.03, color=Fore.GREEN):
    """Types text character by character like Matrix code"""
    for char in text:
        print(color + char, end="", flush=True)
        time.sleep(delay)
    print()

def pause(duration=1.5):
    """Dramatic pause"""
    time.sleep(duration)

def blink_cursor(duration=2):
    """Blinking cursor effect"""
    for _ in range(int(duration * 2)):
        print("_", end="", flush=True)
        time.sleep(0.3)
        print("\b \b", end="", flush=True)
        time.sleep(0.3)

def chat_message(sender, text, typing_delay=0.04):
    """Simulates incoming chat message"""
    print(Fore.CYAN + f"[{sender}]: ", end="", flush=True)
    pause(0.5)
    for char in text:
        print(Fore.WHITE + char, end="", flush=True)
        time.sleep(typing_delay)
    print()
    pause(0.8)

def banner():
    """Minimal banner - shown only once"""
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
    pause(1)

def download_pill_script(pill_type, script_name):
    """Download the chosen pill script"""
    clear()
    pause(0.5)
    
    if pill_type == "red":
        chat_message("MORPHEUS", "Now, I'm going to show you what the Matrix really is.")
        matrix_type(">>> Acquiring attack tools...", 0.02, Fore.RED)
    else:
        chat_message("MORPHEUS", "Let me show you the defenses.")
        matrix_type(">>> Acquiring defense tools...", 0.02, Fore.BLUE)
    
    pause(0.5)
    
    # Create directory if it doesn't exist
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Download the script
    try:
        url = SCRIPT_URLS[pill_type]
        matrix_type(f">>> Connecting to secure server...", 0.02, Fore.CYAN)
        pause(0.5)
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        matrix_type(f">>> Downloading {script_name}...", 0.02, Fore.CYAN)
        
        # Simulate download progress
        for i in range(0, 101, 20):
            print(Fore.GREEN + f"\r>>> Progress: [{('█' * (i//5)).ljust(20)}] {i}%", end="", flush=True)
            time.sleep(0.3)
        print()
        
        script_path = SCRIPTS_DIR / script_name
        script_path.write_text(response.text)
        script_path.chmod(0o755)  # Make executable
        
        pause(0.5)
        matrix_type(f">>> {script_name} acquired.", 0.02, Fore.GREEN)
        pause(0.5)
        
        chat_message("MORPHEUS", "The tool is ready.")
        pause(1)
        return str(script_path)
        
    except requests.exceptions.RequestException as e:
        matrix_type(f">>> ERROR: Download failed.", 0.02, Fore.RED)
        print(Fore.YELLOW + f"    Connection issue: {str(e)}")
        pause(1)
        chat_message("MORPHEUS", "Something went wrong. Check your connection.")
        pause(2)
        return None

def matrix_intro():
    """Matrix-style mysterious intro with chat"""
    clear()
    pause(1)
    
    # Simulated system boot
    matrix_type(">>> Initializing secure channel...", 0.02, Fore.GREEN)
    pause(0.5)
    matrix_type(">>> Encryption handshake complete.", 0.02, Fore.GREEN)
    pause(1)
    print()
    
    # Mysterious chat begins
    chat_message("UNKNOWN", "Wake up...")
    blink_cursor(1)
    
    chat_message("UNKNOWN", "The Matrix has you.")
    pause(1.5)
    
    chat_message("UNKNOWN", "Follow the white rabbit.")
    pause(2)
    
    # Reveal identity slowly
    print(Fore.CYAN + "[UNKNOWN" + Fore.GREEN + " → MORPHEUS" + Fore.CYAN + "]: ", end="", flush=True)
    pause(1)
    matrix_type("Knock, knock, Neo.", 0.05, Fore.WHITE)
    pause(2)

def get_user_name():
    """Ask for name in Matrix style"""
    clear()
    pause(0.5)
    
    chat_message("MORPHEUS", "I've been looking for you.")
    chat_message("MORPHEUS", "I know why you're here.")
    pause(1)
    
    print(Fore.CYAN + "[MORPHEUS]: ", end="", flush=True)
    pause(0.3)
    matrix_type("What is your name?", 0.04, Fore.WHITE)
    pause(0.5)
    
    name = input(Fore.YELLOW + Style.BRIGHT + "\n>>> ").strip()
    
    if not name:
        name = "Neo"
    
    pause(1)
    chat_message("MORPHEUS", f"Hello, {name}.")
    pause(1.5)
    
    return name

def disclaimer(name):
    """Disclaimer framed as a warning from Morpheus"""
    clear()
    pause(0.5)
    
    chat_message("MORPHEUS", f"{name}, what you know you can't explain.")
    chat_message("MORPHEUS", "But you feel it.")
    pause(1)
    
    chat_message("MORPHEUS", "This tool reveals the truth about wireless networks.")
    chat_message("MORPHEUS", "But it comes with responsibility.")
    pause(1.5)
    
    print()
    console.print("⚠️  DISCLAIMER:\n", style="bold red")
    print(Fore.WHITE + "• This software is for EDUCATIONAL and AUTHORIZED use only.")
    print(Fore.WHITE + "• Unauthorized network testing may be illegal.")
    print(Fore.WHITE + "• You are solely responsible for how this tool is used.")
    print(Fore.WHITE + "• The authors assume no liability.\n")
    pause(1)
    
    accept = input(Fore.YELLOW + "Do you accept these terms? (yes/no) >>> ").strip().lower()
    
    if accept not in ["yes", "y"]:
        print()
        chat_message("MORPHEUS", "Perhaps you weren't ready.")
        pause(1)
        matrix_type(">>> Connection terminated.", 0.02, Fore.RED)
        exit(0)
    
    pause(1)
    chat_message("MORPHEUS", "Good.")

def the_choice(name):
    """The pill choice - the core moment"""
    clear()
    pause(1)
    
    chat_message("MORPHEUS", f"This is your last chance, {name}.")
    pause(1.5)
    
    chat_message("MORPHEUS", "After this, there is no turning back.")
    pause(2)
    
    print()
    matrix_type("You take the BLUE PILL...", 0.05, Fore.BLUE)
    pause(0.8)
    matrix_type("    ...the story ends. You defend your network.", 0.04, Fore.BLUE)
    pause(1.5)
    
    print()
    matrix_type("You take the RED PILL...", 0.05, Fore.RED)
    pause(0.8)
    matrix_type("    ...and I show you how deep the rabbit hole goes.", 0.04, Fore.RED)
    pause(2)
    
    print("\n")
    chat_message("MORPHEUS", "Remember...")
    pause(0.5)
    chat_message("MORPHEUS", "All I'm offering is the truth. Nothing more.")
    pause(2)
    
    print()
    print(Fore.CYAN + "─" * 50)
    print(Fore.RED + Style.BRIGHT + "  [R] " + Fore.WHITE + "RED PILL  " + Fore.RED + "→ Attack Simulation")
    print(Fore.BLUE + Style.BRIGHT + "  [B] " + Fore.WHITE + "BLUE PILL " + Fore.BLUE + "→ Defense & Detection")
    print(Fore.CYAN + "─" * 50)
    print()
    
    while True:
        choice = input(Fore.YELLOW + Style.BRIGHT + "Your choice >>> ").strip().lower()
        
        if choice in ['r', 'red']:
            return 'red'
        elif choice in ['b', 'blue']:
            return 'blue'
        else:
            print(Fore.RED + "Invalid choice. Press R or B.")
            pause(0.5)

def red_pill_authorization(name):
    """Authorization check for red pill"""
    clear()
    pause(0.5)
    
    matrix_type(">>> ACCESS LEVEL: RESTRICTED", 0.03, Fore.RED)
    pause(1)
    
    print()
    chat_message("MORPHEUS", f"{name}, you chose to see how deep the rabbit hole goes.")
    chat_message("MORPHEUS", "But this path requires authorization.")
    pause(1.5)
    
    chat_message("MORPHEUS", "You must have EXPLICIT WRITTEN PERMISSION.")
    chat_message("MORPHEUS", "Do you have authorization to test this network?")
    pause(1)
    
    print()
    consent = input(Fore.YELLOW + "Type 'I HAVE AUTHORIZATION' to proceed >>> ").strip().upper()
    
    if consent == "I HAVE AUTHORIZATION":
        pause(1)
        chat_message("MORPHEUS", "Very well.")
        pause(0.5)
        chat_message("MORPHEUS", "Follow me.")
        return True
    else:
        pause(1)
        chat_message("MORPHEUS", "You're not ready.")
        pause(1.5)
        return False

def transfer_control(script_path, pill_type):
    """Transfer control to the chosen script"""
    clear()
    pause(0.5)
    
    if pill_type == 'red':
        matrix_type(">>> Entering the Matrix...", 0.03, Fore.RED)
        pause(0.5)
        matrix_type(">>> Attack simulation mode active.", 0.03, Fore.RED)
    else:
        matrix_type(">>> Initializing defense protocols...", 0.03, Fore.BLUE)
        pause(0.5)
        matrix_type(">>> Detection systems online.", 0.03, Fore.BLUE)
    
    pause(1)
    matrix_type(">>> Transferring control...", 0.03, Fore.GREEN)
    pause(1.5)
    
    print()
    chat_message("MORPHEUS", "See you on the other side.")
    pause(1)
    
    # Execute the script
    os.execvp("bash", ["bash", script_path])

def main():
    # Boot sequence
    banner()
    
    # Matrix intro with mysterious chat
    matrix_intro()
    
    # Get user's name
    name = get_user_name()
    
    # Show disclaimer
    disclaimer(name)
    
    # The choice
    while True:
        choice = the_choice(name)
        
        if choice == 'red':
            if red_pill_authorization(name):
                # Download the red pill script
                script_path = download_pill_script('red', SCRIPT_NAMES['red'])
                if script_path:
                    transfer_control(script_path, 'red')
                    break
                else:
                    pause(2)
                    clear()
                    chat_message("MORPHEUS", "We'll try again.")
                    pause(1)
            else:
                pause(2)
                clear()
                chat_message("MORPHEUS", "Let's try again.")
                pause(1)
        
        elif choice == 'blue':
            pause(1)
            chat_message("MORPHEUS", "A wise choice.")
            pause(1)
            
            # Download the blue pill script
            script_path = download_pill_script('blue', SCRIPT_NAMES['blue'])
            if script_path:
                transfer_control(script_path, 'blue')
                break
            else:
                pause(2)
                clear()
                chat_message("MORPHEUS", "We'll try again.")
                pause(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        matrix_type(">>> Connection interrupted.", 0.02, Fore.RED)
        print()
        exit(0)
    except Exception as e:
        print("\n")
        matrix_type(f">>> SYSTEM ERROR: {str(e)}", 0.02, Fore.RED)
        print()
        exit(1)