# Linux System Integrity Monitor (LSIM)

A Python-based security monitoring tool for Ubuntu Linux that watches your system for signs of compromise, misconfigurations, and active attacks. When it detects something bad enough, it can automatically kill malicious processes, lock compromised accounts, and block network traffic until you can investigate.

**CPSC4240 — Braylon McComiskey, St. Angelo Davis, Christian Dew**

---

## What It Does

LSIM continuously monitors your system and reports one of three states:

| State | When | What Happens |
|-------|------|--------------|
| **SECURE** | Nothing suspicious found | Logs the result, notifies you |
| **AT RISK** | Misconfigurations or weak settings found | Lists what's wrong so you can fix it |
| **LOCKDOWN** | Active threat or intrusion detected | Kills bad processes, locks accounts, blocks network traffic |

The tool is split into **scanners** (things that are actively happening right now) and **auditors** (things that are misconfigured and could be exploited).

**Scanners:**
- File integrity — hashes critical system files and alerts if anything changes (uses SHA-256)
- Process scanner — looks for processes running from /tmp, suspicious tool names (nc, nmap, xmrig, etc.), and privilege escalation
- User scanner — checks for accounts with UID 0 that aren't root, empty passwords, and passwordless sudo
- Network scanner — flags listeners on known backdoor ports (4444, 1337, 31337, etc.) and unexpected services exposed on all interfaces

**Auditors:**
- Firewall — checks if UFW is actually enabled, if iptables defaults are secure, and if SSH is rate-limited
- Permissions — finds unexpected SUID binaries, world-writable files in /etc and /usr/bin, and files with no valid owner
- Packages — checks for pending security updates and whether your apt cache is stale

**When LOCKDOWN triggers, it automatically:**
- Sends SIGTERM then SIGKILL to flagged malicious processes
- Locks compromised user accounts with `passwd --lock` and expires them immediately
- Adds an iptables chain that blocks all new traffic while keeping your existing SSH session alive

---

## Requirements

- Ubuntu 24.04 LTS (might work on other Debian-based distros but we only tested on Ubuntu)
- Python 3.10 or newer
- Root access (sudo) — needed to read shadow files, inspect other processes, and touch iptables
- `ufw` and `iptables` should already be installed, but if not: `sudo apt install ufw`
- `python3-apt` is recommended for the packages auditor: `sudo apt install python3-apt`

---

## Setup

```bash
git clone <repo-url>
cd linux-system-integrity-monitor
sudo bash setup.sh
```

The setup script creates the log/state directories, installs Python packages, and optionally adds `lsim` to your PATH.

**You have to create a baseline before you can scan.** The baseline is what LSIM compares against — without it the file integrity scanner won't know what "normal" looks like.

```bash
sudo python3 lsim.py --baseline
```

Run this on a clean system. If the system is already compromised when you create the baseline, the baseline can't be trusted.

---

## Usage

```bash
# Basic scan (the thing you'll run most often)
sudo python3 lsim.py --scan

# Scan but don't take any automated actions — just show findings
sudo python3 lsim.py --scan --no-respond

# Show everything including low-priority stuff
sudo python3 lsim.py --scan --verbose

# Run in the background and re-scan every 5 minutes
sudo python3 lsim.py --daemon --interval 300

# Output JSON instead of the pretty terminal display (useful for piping to other tools)
sudo python3 lsim.py --scan --json

# If you want to manually trigger lockdown
sudo python3 lsim.py --lockdown

# Release the lockdown when you've dealt with the threat
sudo python3 lsim.py --unlock

# Show results from the last scan without running a new one
sudo python3 lsim.py --report
```

### All flags

| Flag | Description |
|------|-------------|
| `--scan` | Run a full scan (this is the default if you don't pass anything) |
| `--baseline` | Create or update the file integrity baseline |
| `--daemon` | Keep running and re-scan on a schedule |
| `--interval N` | How many seconds between daemon scans (default is 300) |
| `--report` | Print the last scan result from the log |
| `--no-respond` | Scan only, don't kill anything or block traffic |
| `--lockdown` | Manually activate network lockdown |
| `--unlock` | Manually release network lockdown |
| `--verbose` | Include INFO-level findings in the output |
| `--json` | Output findings as JSON instead of the colored display |

---

## Project Structure

```
linux-system-integrity-monitor/
├── lsim.py                      # Main entry point, CLI argument parsing
├── lsim/
│   ├── config.py                # All the constants (watched files, suspicious ports, etc.)
│   ├── finding.py               # The Finding class used by every module + state logic
│   ├── baseline.py              # Creates and compares SHA-256 file baselines
│   ├── logger.py                # Writes to the human log and the JSON Lines event log
│   ├── reporter.py              # The colored terminal output using the rich library
│   ├── scanner/
│   │   ├── file_integrity.py    # Compares current file hashes to baseline
│   │   ├── process_scanner.py   # Process-based heuristics using psutil
│   │   ├── user_scanner.py      # Checks passwd, shadow, and sudoers
│   │   └── network_scanner.py   # Checks active network connections for red flags
│   ├── auditor/
│   │   ├── firewall.py          # Runs ufw and iptables commands to check config
│   │   ├── permissions.py       # Finds SUID binaries, world-writable files, etc.
│   │   └── packages.py          # Checks apt for pending security updates
│   └── responder/
│       ├── process_killer.py    # SIGTERM then SIGKILL, won't touch PID < 100 or itself
│       ├── user_disabler.py     # passwd --lock and usermod --expiredate
│       └── lockdown.py          # Manages the iptables LSIM_LOCKDOWN chain
├── scripts/
│   ├── demo_file_integrity.sh   # Demo: trigger file integrity alerts
│   ├── demo_suspicious_process.sh  # Demo: spawn processes that look malicious
│   ├── demo_network_backdoor.sh # Demo: open listeners on suspicious ports
│   ├── demo_user_risks.sh       # Demo: simulate compromised user accounts
│   ├── demo_permissions.sh      # Demo: dangerous file permissions
│   ├── demo_lockdown_response.sh   # Demo: full lockdown cycle with iptables
│   └── run_all_demos.sh         # Runs demos 1-4 back to back
├── tests/                       # Unit tests (all mocked, no root needed)
├── requirements.txt
└── setup.sh
```

---

## Demo Scripts

The `scripts/` directory has demos that intentionally trigger each detection system so you can see it in action. All of them clean up after themselves.

```bash
# Run all the safe demos back to back
sudo bash scripts/run_all_demos.sh

# Or run individual demos
sudo bash scripts/demo_file_integrity.sh
sudo bash scripts/demo_suspicious_process.sh
sudo bash scripts/demo_network_backdoor.sh
sudo bash scripts/demo_user_risks.sh
sudo bash scripts/demo_permissions.sh

# This one actually triggers iptables — read the warning inside before running
sudo bash scripts/demo_lockdown_response.sh
```

---

## Logs

LSIM writes to two places:

| File | Format | What's in it |
|------|--------|--------------|
| `/var/log/lsim/lsim.log` | Plain text | Human readable, rotates at 10MB |
| `/var/log/lsim/lsim_events.jsonl` | JSON Lines | One JSON object per event, good for scripting |

Example JSON event:
```json
{
  "timestamp": "2024-01-01T12:00:00+00:00",
  "event_type": "scan_result",
  "state": "LOCKDOWN",
  "hostname": "ubuntu-host",
  "findings": [...],
  "actions_taken": ["Kill PID 4321: process running from /tmp", "Network lockdown activated"]
}
```

---

## Releasing a Lockdown

When lockdown activates, all new inbound/outbound connections are blocked. Your current SSH session stays open because the iptables rule allows ESTABLISHED connections, but you won't be able to start new ones until you unlock.

```bash
sudo python3 lsim.py --unlock
```

Before you unlock, check the logs to understand what triggered it and make sure you've actually dealt with the problem:

```bash
sudo python3 lsim.py --report
cat /var/log/lsim/lsim_events.jsonl | tail -1 | python3 -m json.tool
```

---

## Running Tests

The test suite doesn't need root because all the system calls (psutil, subprocess, file reads) are mocked. You can just run:

```bash
pytest tests/ -v --tb=short
```

We have 53 tests covering all the main detection logic, safety checks in the responders, and edge cases like missing baselines or missing dependencies.

---

## Exit Codes

| Code | State |
|------|-------|
| `0` | SECURE |
| `1` | AT RISK |
| `2` | LOCKDOWN |

So you can do things like:

```bash
sudo python3 lsim.py --scan --no-respond || echo "Something is wrong"
```

---

## Limitations

This is an academic project so there are some things it can't do:

- **Kernel rootkits** — if an attacker has kernel-level access they can hide processes and files from the OS APIs we rely on. This tool operates entirely in userspace.
- **Compromised baseline** — if the system was already hacked before you ran `--baseline`, the baseline is worthless. Always create it on a clean system.
- **Not a real SIEM** — this is not a replacement for actual enterprise security tools like Splunk, CrowdStrike, Wazuh, etc. It's a proof of concept built for a class project.

---

## Authors

Braylon McComiskey, St. Angelo Davis, Christian Dew

CPSC4240 — System Security
