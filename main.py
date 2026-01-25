import os
import sys
import time
import subprocess
import webbrowser
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Global flag to show HTML logo only once
logo_shown = False


def clear():
    os.system("clear" if os.name == "posix" else "cls")


def slow_print(text, delay=0.02):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

console = Console()

def banner():
    console.clear()

    title = Text("ROBO", style="bold red")
    title.append("WIFI", style="bold white")
    title.append("-AP", style="bold red")

    wifi = Text("\n📡  ACCESS POINT ACTIVE\n", style="red")

    subtitle = Text(
        "WiFi Security Assessment Framework\n"
        "Red Pill  |  Blue Pill",
        style="bright_red"
    )

    content = Align.center(
        Text.assemble(
            title, "\n",
            wifi,
            subtitle
        ),
        vertical="middle"
    )

    panel = Panel(
        content,
        border_style="red",
        padding=(1, 4),
        title="RoboWiFi-AP",
        title_align="center"
    )

    console.print(panel)



def instructions():
    slow_print(Fore.WHITE + Style.BRIGHT + "📌 IMPORTANT INSTRUCTIONS:\n", 0.01)

    slow_print(Fore.GREEN + "✔ This tool is for EDUCATIONAL & AUTHORIZED use only")
    slow_print(Fore.GREEN + "✔ You MUST have written permission before testing")
    slow_print(Fore.GREEN + "✔ Red Pill simulates attacks in controlled labs")
    slow_print(Fore.GREEN + "✔ Blue Pill helps detect and defend against fake APs\n")

    slow_print(
        Fore.RED + Style.BRIGHT +
        "⚠ Unauthorized use of Red Pill mode may be ILLEGAL\n"
    )

    input(Fore.YELLOW + "Press ENTER to continue...")


def menu():
    print(Fore.RED + Style.BRIGHT + " [1] 🔴 RED PILL  → Attack Simulation (Fake AP)")
    print(Fore.BLUE + Style.BRIGHT + " [2] 🔵 BLUE PILL → Defense Mode (Fake AP Detection)")
    print(Fore.WHITE + " [0] ❌ Exit\n")


def confirm_red_pill():
    clear()
    print(Fore.RED + Style.BRIGHT + "⚠ RED PILL AUTHORIZATION CHECK ⚠\n")
    slow_print("This mode simulates attacker behavior.")
    slow_print("You must have EXPLICIT WRITTEN AUTHORIZATION.\n")

    consent = input(Fore.YELLOW + "Type 'I HAVE AUTHORIZATION' to continue: ")

    if consent.strip().upper() == "I HAVE AUTHORIZATION":
        return True
    else:
        print(Fore.RED + "\nAuthorization not confirmed. Returning to menu.")
        time.sleep(2)
        return False


def run_script(script_name):
    try:
        if script_name.endswith(".py"):
            subprocess.run([sys.executable, script_name])
        else:
            subprocess.run(["bash", script_name])
    except FileNotFoundError:
        print(Fore.RED + f"[!] {script_name} not found.")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")


def main():
    banner()
    instructions()

    while True:
        banner()
        menu()
        choice = input(Fore.GREEN + Style.BRIGHT + "Select an option ➜ ")

        if choice == "1":
            if confirm_red_pill():
                print(Fore.RED + "\n[+] Launching RED PILL...\n")
                run_script("fake_ap.sh")
                input(Fore.YELLOW + "\nPress ENTER to return to menu...")

        elif choice == "2":
            print(Fore.BLUE + "\n[+] Launching BLUE PILL...\n")
            run_script("blue_pill.py")
            input(Fore.YELLOW + "\nPress ENTER to return to menu...")

        elif choice == "0":
            print(Fore.GREEN + "\n[✓] Exiting framework. Stay ethical.\n")
            break

        else:
            print(Fore.RED + "\n[!] Invalid selection.")
            time.sleep(1)


if __name__ == "__main__":
    main()
