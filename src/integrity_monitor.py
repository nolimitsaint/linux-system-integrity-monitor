# DEPRECATED: Superseded by lsim/ package (Sprint 2+). Run: sudo python3 lsim.py --scan
#!/usr/bin/env python3
"""
Linux System Integrity Monitor
File Integrity Check - Sprint 1
"""

import hashlib
import os
import sys
import time

# Files to monitor
FILES_TO_MONITOR = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/group",
]

# Store hashes in memory
file_hashes = {}

def calculate_md5(filepath):
    """Calculate MD5 hash of a file"""
    try:
        with open(filepath, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except (IOError, PermissionError) as e:
        print(f"[ERROR] Cannot read {filepath}: {e}")
        return None

def initialize_hashes():
    """Store initial hashes of all monitored files"""
    print("[*] Initializing file hashes...")
    for filepath in FILES_TO_MONITOR:
        if os.path.exists(filepath):
            file_hashes[filepath] = calculate_md5(filepath)
            print(f"[+] Stored hash for {filepath}")
        else:
            print(f"[-] Warning: {filepath} does not exist")

def check_integrity():
    """Check if any monitored files have changed"""
    alerts = []
    for filepath in FILES_TO_MONITOR:
        if not os.path.exists(filepath):
            alerts.append(f"Missing file: {filepath}")
            continue
        
        current_hash = calculate_md5(filepath)
        original_hash = file_hashes.get(filepath)
        
        if original_hash and current_hash != original_hash:
            alerts.append(f"INTEGRITY VIOLATION: {filepath} has been modified!")
    
    return alerts

def main():
    print("=" * 50)
    print("Linux System Integrity Monitor")
    print("Monitoring files:", ", ".join(FILES_TO_MONITOR))
    print("=" * 50)
    
    # Initialize baseline hashes
    initialize_hashes()
    
    print("\n[*] Starting continuous monitoring (Ctrl+C to stop)")
    print("[*] Checking every 5 seconds...\n")
    
    try:
        while True:
            alerts = check_integrity()
            
            if alerts:
                for alert in alerts:
                    print(f"[ALERT] {alert}")
            else:
                print("[OK] All monitored files intact")
            
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped")
        sys.exit(0)

if __name__ == "__main__":
    # Must be run as root to read certain files
    if os.geteuid() != 0:
        print("[-] This script must be run as root (sudo)")
        sys.exit(1)
    
    main()
