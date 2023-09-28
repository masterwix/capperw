import os
import subprocess
import shlex
from scapy.all import *
from tabulate import tabulate
from colorama import Fore, Style

def clear_terminal():
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        _ = os.system('cls')

def configure_crunch():
    min_length = input("Enter the minimum length of the key to decrypt (8-63): ")
    max_length = input("Enter the maximum length of the key to decrypt (8-63): ")

    print("\033[1m\033[91mSelect the character set to use:\033[0m")
    print("\033[93m0. Exit\033[0m")
    print("\033[93m1. Lowercase chars\033[0m")
    print("\033[93m2. Uppercase chars\033[0m")
    print("\033[93m3. Numeric chars\033[0m")
    print("\033[93m4. Symbol chars\033[0m")
    print("\033[93m5. Lowercase + uppercase chars\033[0m")
    print("\033[93m6. Lowercase + numeric chars\033[0m")
    print("\033[93m7. Uppercase + numeric chars\033[0m")
    print("\033[93m8. Symbol + numeric chars\033[0m")
    print("\033[93m9. Lowercase + uppercase + numeric chars\033[0m")
    print("\033[93m10. Lowercase + uppercase + symbol chars\033[0m")
    print("\033[93m11. Lowercase + uppercase + numeric + symbol chars\033[0m")
    
    charset_choice = input("\033[91mEnter the number corresponding to the character set:\033[0m")

    try:
        choice = int(charset_choice)
        if choice == 0:
            exit(0)
        if not (8 <= int(min_length) <= 63) or not (8 <= int(max_length) <= 63) or not (1 <= choice <= 11):
            print("\033[91mInvalid input. Please provide valid inputs.\033[0m")
            return configure_crunch()
    except ValueError:
        print("\033[91mInvalid input. Please enter a number.\033[0m")
        return configure_crunch()

    if choice == 10 or choice == 11:
        # Define el conjunto de caracteres personalizado
        custom_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+[]{}|;':,.<>?/0123456789"
        # Crea un archivo temporal si no existe y escribe el conjunto de caracteres en él
        with open('custom_charset.txt', 'w') as charset_file:
            charset_file.write(custom_charset)
        charset = 'custom_charset.txt'
    else:
        charset_options = [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            r"""!@#$%^&*()_+[]{}|;':,.<>?/""",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz0123456789",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "0123456789!@#$%^&*()_+[]{}|;':,.<>?/",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        ]
        charset = charset_options[choice - 1]

    return min_length, max_length, charset

def run_bruteforce_attack(cap_file, ssid):
    min_length, max_length, charset = configure_crunch()

    command = "crunch {min_length} {max_length} {charset} | aircrack-ng -e {ssid} -w - {cap_file}".format(
        min_length=min_length,
        max_length=max_length,
        charset=charset,
        ssid=shlex.quote(ssid),
        cap_file=shlex.quote(cap_file)
    )

    try:
        subprocess.run(command, shell=True)
    except Exception as e:
        print(f"Error: {e}")

    print("Brute-force attack complete.")

def list_capture_files():
    cap_folder = "caps"
    cap_files = [f for f in os.listdir(cap_folder) if f.endswith('.cap')]
    return cap_files

def extract_ssid_from_capture(cap_file):
    ssid = None
    try:
        packets = rdpcap(cap_file)
        for packet in packets:
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                break
    except Exception as e:
        print(f"Error extracting SSID from capture file: {e}")
    return ssid

def extract_mac_from_capture(cap_file):
    mac = None
    try:
        packets = rdpcap(cap_file)
        for packet in packets:
            if packet.haslayer(Dot11):
                mac = packet[Dot11].addr2
                break
    except Exception as e:
        print(f"Error extracting MAC address from capture file: {e}")
    return mac

def main():
    clear_terminal()
    print("\033[1m\033[91mCapperW ver 2.2\033[0m")
    print("Please wait loading caps data....")

    cap_files = list_capture_files()

    if not cap_files:
        print("No .cap files found in the 'caps' folder.")
        return

    data = []

    for i, cap_file in enumerate(cap_files, start=1):
        cap_file_path = os.path.join("caps", cap_file)
        ssid = extract_ssid_from_capture(cap_file_path)
        mac = extract_mac_from_capture(cap_file_path)
        data.append([i, cap_file, ssid, mac])

    if len(cap_files) == 1:
        print(f"Found only one .cap file: {cap_files[0]}.")
        use_this_file = input("Use this file? (y/n): ")
        if use_this_file.lower() == 'y':
            cap_file = os.path.join("caps", cap_files[0])
            ssid = extract_ssid_from_capture(cap_file)
            if ssid:
                print(f"SSID extracted from capture file: {Fore.GREEN}{ssid}{Style.RESET_ALL}")
                run_bruteforce_attack(cap_file, ssid)
                return

    headers = ["#", "CAP File", "SSID", "MAC"]
    print(tabulate(data, headers=headers, tablefmt="grid"))

    choice = input("Enter the number corresponding to the capture file: ")

    try:
        choice = int(choice)
        if 1 <= choice <= len(cap_files):
            cap_file = os.path.join("caps", cap_files[choice - 1])
            ssid = extract_ssid_from_capture(cap_file)
            if ssid:
                print(f"SSID extracted from capture file: {Fore.GREEN}{ssid}{Style.RESET_ALL}")
                run_bruteforce_attack(cap_file, ssid)
            else:
                print("Failed to extract SSID. Try another capture file.")
        else:
            print("Invalid choice. Please select a valid capture file.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")

if __name__ == "__main__":
    main()
