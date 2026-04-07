#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: File Integrity Detection
#
# Demonstrates:
#   - CRITICAL finding when a watched file's hash changes (/etc/hosts)
#   - CRITICAL finding when a watched file is deleted (/etc/hostname copy)
#   - HIGH finding when a watched file's permissions change (/etc/hosts)
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
HOSTS_ORIG_MODE=""

cleanup() {
    echo ""
    echo "[*] Cleaning up..."

    # Restore /etc/hosts
    if [ -n "$HOSTS_BACKUP" ] && [ -f "$HOSTS_BACKUP" ]; then
        cp "$HOSTS_BACKUP" /etc/hosts
        rm -f "$HOSTS_BACKUP"
        echo "[+] /etc/hosts restored"
    fi

    # Restore /etc/hosts permissions
    if [ -n "$HOSTS_ORIG_MODE" ]; then
        chmod "$HOSTS_ORIG_MODE" /etc/hosts
        echo "[+] /etc/hosts permissions restored"
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
section_header "DEMO 1/2: Modify /etc/hosts  |  Expected: CRITICAL (hash changed)"

echo "[*] Saving original /etc/hosts..."
HOSTS_BACKUP=$(mktemp /tmp/hosts_backup.XXXXXX)
cp /etc/hosts "$HOSTS_BACKUP"
HOSTS_ORIG_MODE=$(stat -c "%a" /etc/hosts)

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

# Restore so demo 2 starts clean
cp "$HOSTS_BACKUP" /etc/hosts

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 2: Change permissions on a watched file → HIGH (permissions changed)
# ---------------------------------------------------------------------------
section_header "DEMO 2/2: Make /etc/hosts world-writable  |  Expected: HIGH (perms changed)"

echo "[*] Setting /etc/hosts to 0o777 (world-writable)..."
chmod 777 /etc/hosts
echo "[+] /etc/hosts is now world-writable"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Restore permissions before cleanup trap fires
chmod "$HOSTS_ORIG_MODE" /etc/hosts
HOSTS_ORIG_MODE=""  # Don't restore again in cleanup

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ File Integrity demo complete."
echo ""
