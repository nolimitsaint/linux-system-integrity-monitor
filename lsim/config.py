"""
LSIM Configuration — all constants live here, no magic strings elsewhere.
"""

import os

# ---------------------------------------------------------------------------
# Watched critical system files for integrity monitoring
# ---------------------------------------------------------------------------
WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.hourly/",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/ld.so.preload",
    "/etc/pam.d/",
    "/boot/grub/grub.cfg",
    "/sbin/init",
    "/usr/bin/sudo",
    "/usr/bin/su",
]

# ---------------------------------------------------------------------------
# Hashing and storage
# ---------------------------------------------------------------------------
HASH_ALGO = "sha256"

BASELINE_FILE = "/var/lib/lsim/baseline.json"
BASELINE_FILE_FALLBACK = os.path.expanduser("~/.lsim/baseline.json")

LOG_DIR = "/var/log/lsim/"
LOG_FILE = os.path.join(LOG_DIR, "lsim.log")
LOG_FILE_JSONL = os.path.join(LOG_DIR, "lsim_events.jsonl")

LOCKDOWN_STATE_FILE = "/var/lib/lsim/lockdown.state"

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Ordered for sorting (lower index = higher severity)
SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

# ---------------------------------------------------------------------------
# Process heuristics
# ---------------------------------------------------------------------------
SUSPICIOUS_PROC_NAMES: frozenset = frozenset([
    "nc", "ncat", "netcat", "nmap", "masscan",
    "msfconsole", "msfvenom", "metasploit",
    "cryptominer", "xmrig", "minerd",
    "hydra", "john", "hashcat",
    "mimikatz", "empire", "cobalt",
])

SUSPICIOUS_PROC_PATHS = [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/shm/",
]

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
# dict: port → description (description surfaces in Finding.detail)
SUSPICIOUS_PORTS: dict = {
    4444: "Metasploit default listener",
    1337: "Common backdoor/hacker port",
    31337: "Back Orifice / elite hacker port",
    5554: "Sasser worm / known malware port",
    8888: "Common reverse shell port",
    9999: "Common backdoor port",
    6667: "IRC (often used by botnets)",
    6666: "IRC / common malware port",
    9050: "Tor SOCKS proxy",
    9051: "Tor control port",
}

# ---------------------------------------------------------------------------
# Expected SUID binaries — anything else is flagged
# ---------------------------------------------------------------------------
KNOWN_SETUID_BINARIES = [
    # Core user/auth utilities
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/passwd",
    "/usr/bin/pkexec",
    # SSH
    "/usr/lib/openssh/ssh-keysign",
    # Network
    "/usr/sbin/pppd",
    "/bin/ping",
    "/usr/bin/ping",
    # Filesystem
    "/bin/mount",
    "/bin/umount",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",         # FUSE userspace filesystem mount (Ubuntu 22.04+)
    # D-Bus / system services
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    # PolicyKit — path changed from policykit-1 to polkit-1 in Ubuntu 22.04+
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    # Xorg / display
    "/usr/lib/xorg/Xorg.wrap",
    # Misc system utilities
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/pt_chown",
    "/usr/bin/at",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/expiry",
    "/usr/sbin/unix_chkpwd",
    # VMware Tools (present on VMware VMs)
    "/usr/bin/vmware-user-suid-wrapper",
    # Snap
    "/snap/core20/current/usr/bin/sudo",
    "/snap/core22/current/usr/bin/sudo",
    "/snap/core24/current/usr/bin/sudo",
]

# ---------------------------------------------------------------------------
# Lockdown
# ---------------------------------------------------------------------------
LOCKDOWN_CHAIN = "LSIM_LOCKDOWN"

# Admin user: the account whose processes/connections are always preserved.
# Read SUDO_USER at import time so the responder knows who not to disable.
ADMIN_USER: str = os.environ.get("SUDO_USER", "root") or "root"
