import os
import psutil
import ctypes
import logging
import time
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Logging setup
logging.basicConfig(
    filename="keylogger_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants
WH_KEYBOARD_LL = 13
KERNEL32 = ctypes.windll.kernel32

# Ask before killing a process
def prompt_kill(pid, name):
    try:
        choice = input(Fore.YELLOW + f"[PROMPT] Kill process {name} (PID: {pid})? (y/n): ").strip().lower()
        if choice == 'y':
            proc = psutil.Process(pid)
            proc.terminate()
            logging.warning(f"Process terminated: {name} (PID: {pid})")
            print(Fore.RED + f"[ACTION] Terminated {name} (PID: {pid})")
        else:
            logging.info(f"Process skipped: {name} (PID: {pid})")
            print(Fore.CYAN + f"[INFO] Skipped {name} (PID: {pid})")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(Fore.YELLOW + f"[WARN] Could not terminate {name} (PID: {pid})")

# Fixed Hook Detection
def detect_hooks():
    suspicious_dlls = ["hook.dll", "keyhook.dll", "keyboardhook.dll"]
    detected = False
    print(Fore.CYAN + "[INFO] Checking for suspicious hook DLLs...")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for mmap in proc.memory_maps():
                if any(s in mmap.path.lower() for s in suspicious_dlls):
                    msg = f"[!] Possible hook DLL detected in {proc.info['name']} (PID: {proc.info['pid']})"
                    print(Fore.RED + msg)
                    logging.warning(msg)
                    detected = True
                    prompt_kill(proc.info['pid'], proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not detected:
        print(Fore.GREEN + "[OK] No suspicious hook DLLs found.")
    return detected

# Process & DLL listing
def list_processes_and_dlls():
    suspicious_keywords = ["keylog", "hook", "log", "key"]
    print(Fore.CYAN + "[INFO] Scanning processes and DLLs...")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        pid = proc.info['pid']
        name = proc.info.get('name', '')
        exe = proc.info.get('exe', '')

        if pid in (0, 4):
            continue

        try:
            found = False
            if any(k in (name or "").lower() for k in suspicious_keywords) or \
               any(k in (exe or "").lower() for k in suspicious_keywords):
                found = True
                msg = f"[!] Suspicious process: {name} (PID: {pid}) Path: {exe}"
                print(Fore.YELLOW + msg)
                logging.warning(msg)
                prompt_kill(pid, name)

            for dll in proc.memory_maps():
                dll_path = dll.path or ""
                if any(k in dll_path.lower() for k in suspicious_keywords):
                    found = True
                    msg = f"[!] Suspicious DLL: {dll_path} in Process: {name} (PID: {pid})"
                    print(Fore.YELLOW + msg)
                    logging.warning(msg)
                    prompt_kill(pid, name)

            if not found:
                print(Fore.GREEN + f"[OK] {name} (PID: {pid}) seems clean.")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

# Python keylogger detection
def detect_python_keyloggers():
    print(Fore.CYAN + "[INFO] Scanning for Python-based keyloggers...")
    suspicious_modules = ["pynput", "keyboard", "pyxhook", "keylogger", "pynhook"]
    detected = False

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = (proc.info.get('name') or "").lower()
            cmdline = " ".join(proc.info.get('cmdline') or []).lower()

            if "python" in name or "python" in cmdline:
                if any(mod in cmdline for mod in suspicious_modules):
                    msg = f"[!] Suspicious Python keylogger detected: {name} (PID: {proc.info['pid']}) CMD: {cmdline}"
                    print(Fore.RED + msg)
                    logging.warning(msg)
                    detected = True
                    prompt_kill(proc.info['pid'], name)
                else:
                    for mmap in proc.memory_maps():
                        if any(mod in mmap.path.lower() for mod in suspicious_modules):
                            msg = f"[!] Suspicious Python module in {name} (PID: {proc.info['pid']}): {mmap.path}"
                            print(Fore.RED + msg)
                            logging.warning(msg)
                            detected = True
                            prompt_kill(proc.info['pid'], name)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

    if not detected:
        print(Fore.GREEN + "[OK] No Python-based keyloggers found.")
    return detected

# Fake event generation (HoneyID simulation)
def honeyid_simulation():
    try:
        for i in range(3):
            bogus_key = chr(65 + i)
            msg = f"[HoneyID] Generated bogus key event: {bogus_key}"
            print(Fore.MAGENTA + msg)
            logging.info(msg)
            time.sleep(0.5)
    except Exception as e:
        logging.error(f"Error in honeyid_simulation: {e}")

# Behavior analysis
def detect_suspicious_behavior():
    print(Fore.CYAN + "[INFO] Analyzing process behavior...")
    for proc in psutil.process_iter(['pid', 'name']):
        pid = proc.info['pid']
        name = proc.info.get('name', '')

        if pid in (0, 4):
            continue

        try:
            for conn in proc.net_connections(kind='inet'):
                if conn.status == psutil.CONN_ESTABLISHED:
                    msg = f"[!] Process {name} (PID: {pid}) has an established network connection."
                    print(Fore.RED + msg)
                    logging.warning(msg)
                    prompt_kill(pid, name)

            for mmap in proc.memory_maps():
                if 'log' in mmap.path.lower():
                    msg = f"[!] Suspicious log file in {name} (PID: {pid}): {mmap.path}"
                    print(Fore.RED + msg)
                    logging.warning(msg)
                    prompt_kill(pid, name)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            continue

# Main single-run
if __name__ == "__main__":
    print(Fore.CYAN + "=== Advanced Keylogger Detection System ===")
    logging.info("Starting detection system...")

    print(Fore.CYAN + f"\n[SCAN START] ===== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====")
    detect_hooks()
    list_processes_and_dlls()
    detect_python_keyloggers()
    honeyid_simulation()
    detect_suspicious_behavior()
    print(Fore.CYAN + "[SCAN END] =================================\n")
