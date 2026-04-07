#!/usr/bin/env bash
# =============================================================================
# LSIM Demo Runner — runs all detection demos in sequence
#
# Usage: sudo bash scripts/run_all_demos.sh [--no-pause]
#
# Each demo script is self-contained with its own cleanup.
# Use --no-pause to skip the "press Enter to continue" prompts (for recording).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSIM="$SCRIPT_DIR/../lsim.py"
# shellcheck source=lib_common.sh
source "$SCRIPT_DIR/lib_common.sh"

NO_PAUSE=false
if [[ "${1:-}" == "--no-pause" ]]; then
    NO_PAUSE=true
fi

if [ "$EUID" -ne 0 ]; then
    echo "[-] Run as root: sudo bash $0"
    exit 1
fi

pause() {
    if [ "$NO_PAUSE" = false ]; then
        echo ""
        read -r -p "    [Press Enter to continue to next demo...]"
    fi
}

# ---------------------------------------------------------------------------
# psutil check — do this once here so individual scripts don't each prompt
# ---------------------------------------------------------------------------
clear
section_header "LSIM Demo Suite — Pre-flight Check"
check_psutil

# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
clear
section_header "SETUP: Creating LSIM Baseline"
echo "[*] Ensuring a baseline exists before running demos..."
echo ""
python3 "$LSIM" --baseline
pause

# ---------------------------------------------------------------------------
# Run each demo
# ---------------------------------------------------------------------------

clear
section_header "DEMO 1 of 4: File Integrity Detection"
echo "    Triggers: CRITICAL (hash changed), HIGH (permissions changed)"
pause
bash "$SCRIPT_DIR/demo_file_integrity.sh"
pause

clear
section_header "DEMO 2 of 4: Suspicious Process Detection"
echo "    Triggers: CRITICAL (process from /tmp), HIGH (suspicious name, LD_PRELOAD, deleted exec)"
pause
bash "$SCRIPT_DIR/demo_suspicious_process.sh"
pause

clear
section_header "DEMO 3 of 4: Network Threat Detection"
echo "    Triggers: HIGH (suspicious port 4444/9999, raw socket), MEDIUM (unexpected listener)"
pause
bash "$SCRIPT_DIR/demo_network_backdoor.sh"
pause

clear
section_header "DEMO 4 of 4: Dangerous Permissions"
echo "    Triggers: CRITICAL (world-writable /etc file, unknown SUID), HIGH (/tmp sticky bit)"
pause
bash "$SCRIPT_DIR/demo_permissions.sh"
pause

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
clear
section_header "ALL DEMOS COMPLETE"
echo "  Demos run:"
echo "    1. File Integrity   — hash and permission changes on watched files"
echo "    2. Process Scanner  — /tmp execution, suspicious names, LD_PRELOAD, deleted execs"
echo "    3. Network Scanner  — backdoor ports 4444/9999, raw sockets, unexpected listeners"
echo "    4. Permissions      — world-writable /etc, unknown SUID, missing /tmp sticky bit"
echo ""
echo "  Run individually when ready:"
echo "    sudo bash scripts/demo_user_risks.sh        — UID-0 accounts, empty passwords, NOPASSWD sudo"
echo "    sudo bash scripts/demo_lockdown_response.sh — full automated lockdown cycle (modifies iptables)"
echo ""
echo "  Logs from all scans:"
echo "    Human:   /var/log/lsim/lsim.log"
echo "    Machine: /var/log/lsim/lsim_events.jsonl"
echo ""
