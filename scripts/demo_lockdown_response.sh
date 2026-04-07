#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Full Automated Lockdown Response
#
# This demo shows LSIM's LOCKDOWN state and automated response system.
# Unlike other demos that use --no-respond, this one lets LSIM act:
#
#   1. Spawns a "malicious" process from /tmp (auto_remediate=True)
#   2. Runs lsim.py --scan WITHOUT --no-respond
#   3. LSIM detects CRITICAL findings and activates:
#      - Process termination (kills the /tmp process)
#      - Network lockdown (iptables LSIM_LOCKDOWN chain)
#   4. Shows the lockdown state
#   5. Runs --unlock to restore normal network operation
#
# ⚠  WARNING: This WILL modify iptables rules temporarily.
#             Your existing SSH session is preserved (ESTABLISHED/RELATED rule).
#             Run on a VM or dedicated test system if uncertain.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSIM="$SCRIPT_DIR/../lsim.py"
# shellcheck source=lib_common.sh
source "$SCRIPT_DIR/lib_common.sh"

if [ "$EUID" -ne 0 ]; then
    echo "[-] Run as root: sudo bash $0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit to ensure lockdown is released
# ---------------------------------------------------------------------------
TMP_MALWARE=""
BGPIDS=()

cleanup() {
    echo ""
    echo "[*] Emergency cleanup..."

    for pid in "${BGPIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done

    [ -n "$TMP_MALWARE" ] && rm -f "$TMP_MALWARE"

    # Always release lockdown on exit so the demo environment is restored
    if python3 "$LSIM" --unlock 2>/dev/null; then
        echo "[+] Lockdown released"
    fi

    echo "[+] Cleanup complete"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Safety confirmation
# ---------------------------------------------------------------------------
check_psutil
section_header "LSIM DEMO: Full Automated Lockdown Response"
echo ""
echo "  ⚠  This demo will:"
echo "     1. Spawn a fake malicious process from /tmp"
echo "     2. Run a LIVE scan (no --no-respond)"
echo "     3. LSIM will activate iptables lockdown"
echo "     4. Your current SSH session will be preserved"
echo "     5. Lockdown will be released automatically at the end"
echo ""
read -r -p "  Continue? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "[*] Aborted."
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 1: Create a "malicious" process in /tmp
# ---------------------------------------------------------------------------
section_header "Step 1: Deploying simulated malware to /tmp/"
echo ""

TMP_MALWARE="/tmp/nc"
cp /bin/sleep "$TMP_MALWARE"
chmod +x "$TMP_MALWARE"

echo "[*] Launching '$TMP_MALWARE 300' (simulates a backdoor)..."
"$TMP_MALWARE" 300 &
MALWARE_PID=$!
BGPIDS+=("$MALWARE_PID")
echo "[+] 'Malware' running: PID $MALWARE_PID at $TMP_MALWARE"

# ---------------------------------------------------------------------------
# Step 2: Show pre-lockdown iptables state
# ---------------------------------------------------------------------------
section_header "Step 2: Pre-lockdown iptables state"
echo ""
echo "[*] Current iptables INPUT chain:"
iptables -L INPUT -n --line-numbers 2>/dev/null || echo "    (empty or unavailable)"

# ---------------------------------------------------------------------------
# Step 3: Run LSIM with full response enabled
# ---------------------------------------------------------------------------
section_header "Step 3: Running LSIM scan WITH automated response"
echo ""
echo "[*] Running: python3 lsim.py --scan"
echo "    (LSIM will detect CRITICAL findings and respond)"
echo ""

python3 "$LSIM" --scan || true

wait_for_enter

# ---------------------------------------------------------------------------
# Step 4: Show what happened
# ---------------------------------------------------------------------------
section_header "Step 4: Post-response system state"
echo ""

echo "[*] Is LSIM lockdown active?"
if [ -f /var/lib/lsim/lockdown.state ]; then
    echo "[!] LOCKDOWN IS ACTIVE"
    echo ""
    echo "    State file contents:"
    cat /var/lib/lsim/lockdown.state
else
    echo "[-] Lockdown state file not found"
fi

echo ""
echo "[*] iptables LSIM_LOCKDOWN chain:"
iptables -L LSIM_LOCKDOWN -n 2>/dev/null || echo "    (chain not found)"

echo ""
echo "[*] Is the 'malware' process still running?"
if kill -0 "$MALWARE_PID" 2>/dev/null; then
    echo "[-] PID $MALWARE_PID still alive (auto_remediate may not have triggered)"
    echo "    Killing manually for cleanup..."
    kill "$MALWARE_PID" 2>/dev/null || true
else
    echo "[+] PID $MALWARE_PID has been terminated by LSIM"
fi

wait_for_enter

# ---------------------------------------------------------------------------
# Step 5: Release lockdown
# ---------------------------------------------------------------------------
section_header "Step 5: Releasing lockdown"
echo ""

echo "[*] Running: python3 lsim.py --unlock"
python3 "$LSIM" --unlock || true

echo ""
echo "[*] Post-unlock iptables INPUT chain:"
iptables -L INPUT -n --line-numbers 2>/dev/null

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
section_header "Demo complete"
echo ""
echo "  The lockdown response cycle was:"
echo "    DETECT (CRITICAL) → RESPOND → LOCKDOWN → UNLOCK"
echo ""
