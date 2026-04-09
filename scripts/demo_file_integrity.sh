#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: File Integrity Detection
#
# Demonstrates:
#   - CRITICAL finding when a watched file's hash changes (/etc/hosts)
#
# The script saves originals, makes changes, runs the scan, then restores
# everything automatically — even on Ctrl+C.
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
# Cleanup — always runs on exit
# ---------------------------------------------------------------------------
HOSTS_BACKUP=""

cleanup() {
    echo ""
    echo "[*] Cleaning up..."

    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cp "$HOSTS_BACKUP" /etc/hosts
        rm -f "$HOSTS_BACKUP"
        echo "[+] /etc/hosts restored"
    fi

    echo "[+] Cleanup complete"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Baseline check
# ---------------------------------------------------------------------------
section_header "LSIM DEMO: File Integrity Detection"
echo "[*] Step 1: Ensuring a baseline exists..."

if ! python3 "$LSIM" --baseline 2>&1 | grep -q "Baseline saved"; then
    echo "[*] Creating baseline now..."
    python3 "$LSIM" --baseline
fi
echo "[+] Baseline ready"

# ---------------------------------------------------------------------------
# Demo 1: Modify a watched file → CRITICAL (hash change)
# ---------------------------------------------------------------------------
section_header "DEMO 1/1: Modify /etc/hosts  |  Expected: CRITICAL (hash changed)"

echo "[*] Saving original /etc/hosts..."
HOSTS_BACKUP=$(mktemp /tmp/hosts_backup.XXXXXX)
cp /etc/hosts "$HOSTS_BACKUP"

echo "[*] Appending a fake malicious hosts entry..."
echo "# === INJECTED BY ATTACKER ===" >> /etc/hosts
echo "192.168.1.100  evil-c2-server.com" >> /etc/hosts
echo "[+] /etc/hosts modified"
echo ""
echo "    Diff:"
diff "$HOSTS_BACKUP" /etc/hosts || true
echo ""

echo "[*] Running LSIM scan (--no-respond: detection only, no lockdown)..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ File Integrity demo complete."
echo ""
