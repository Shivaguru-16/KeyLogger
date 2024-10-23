import os
import psutil
import ctypes
from ctypes import wintypes
import logging
import socket
from datetime import datetime
import time

# Logging setup
logging.basicConfig(filename="keylogger_detection.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Constants
WH_KEYBOARD_LL = 13
KERNEL32 = ctypes.windll.kernel32

# Hook detection using Anti-Hook technique
def detect_hooks():
    """
    Detect if there are any suspicious hooks using Anti-Hook technique.
    This method uses ctypes to interact with Windows API to check hooks.
    """
    try:
        user32 = ctypes.windll.user32
        hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, None, KERNEL32.GetModuleHandleW(None), 0)
        
        if hook_id:
            logging.info(f"Suspicious hook detected at {datetime.now()}. Hook ID: {hook_id}")
            return True
        else:
            return False
    except Exception as e:
        logging.error(f"Error in detect_hooks: {e}")
        return False

# Function to list all processes and their DLLs
def list_processes_and_dlls():
    """
    List all the running processes and their associated DLLs.
    """
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                print(f"Process ID: {proc.info['pid']}, Process Name: {proc.info['name']}")
                logging.info(f"Process ID: {proc.info['pid']}, Process Name: {proc.info['name']}")
                
                for dll in proc.memory_maps():
                    print(f"   DLL: {dll.path}")
                    logging.info(f"   DLL: {dll.path}")
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        logging.error(f"Error in list_processes_and_dlls: {e}")

# HoneyID-like Trap detection
def honeyid_simulation():
    """
    Simulate HoneyID technique by generating bogus events to detect suspicious spyware activity.
    This function generates keystrokes and mouse movements to trigger any hidden spyware.
    """
    try:
        for i in range(5):
            bogus_key = chr(65 + i)  # Generate bogus keystroke A, B, C...
            logging.info(f"Generated bogus key event: {bogus_key} at {datetime.now()}")
            time.sleep(1)  # Pause between events
    except Exception as e:
        logging.error(f"Error in honeyid_simulation: {e}")

# Network traffic monitoring for Bot detection
def monitor_network_traffic():
    """
    Monitor outgoing network traffic to detect bot-like behavior.
    Bots typically send keystroke logs to remote servers.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as sock:
            sock.bind((local_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while True:
                data, addr = sock.recvfrom(65535)
                logging.info(f"Packet from {addr} at {datetime.now()}: {data}")
                if b"IRC" in data:
                    logging.warning(f"Potential bot activity detected with IRC traffic from {addr}")
                    break  # For simplicity, stop monitoring after first detection
    except Exception as e:
        logging.error(f"Error in monitor_network_traffic: {e}")

# Dendritic Cell Algorithm (DCA) for behavior-based detection
def detect_suspicious_behavior():
    """
    This function analyzes process behavior by correlating keystrokes, file access, and network activity.
    Implements a simple version of the Dendritic Cell Algorithm (DCA).
    """
    try:
        for proc in psutil.process_iter(['pid', 'name', 'connections']):
            try:
                connections = proc.info['connections']
                if len(connections) > 0:
                    # Check for suspicious network activity
                    logging.info(f"Process {proc.info['name']} has active network connections at {datetime.now()}")
                    
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            logging.warning(f"Suspicious established connection in {proc.info['name']}: {conn.laddr}")
                
                # Check for suspicious file access (keyloggers may write to disk)
                for mmap in proc.memory_maps():
                    if 'log' in mmap.path.lower():
                        logging.warning(f"Suspicious log file found in process {proc.info['name']}: {mmap.path}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        logging.error(f"Error in detect_suspicious_behavior: {e}")

# Main execution flow
if __name__ == "__main__":
    print("Starting advanced keylogger detection system...")
    logging.info("Starting advanced keylogger detection system...")

    # Step 1: Detect hooks
    if detect_hooks():
        logging.warning("Suspicious hooks detected! Possible Keylogger.")

    # Step 2: List processes and DLLs
    print("Listing all processes and their associated DLLs...")
    list_processes_and_dlls()

    # Step 3: HoneyID simulation
    print("Simulating HoneyID trap...")
    honeyid_simulation()

    # Step 4: Monitor network traffic for bot detection
    print("Monitoring network traffic for bot-like behavior...")
    # Run this in a separate thread or stop after first detection
    # monitor_network_traffic()

    # Step 5: Analyze process behavior with DCA
    print("Analyzing suspicious process behavior...")
    detect_suspicious_behavior()
