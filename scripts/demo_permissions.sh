#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Dangerous File Permissions Detection
#
# Demonstrates:
#   - CRITICAL finding: world-writable file in /etc/ (critical directory)
#   - CRITICAL finding: unexpected SUID binary not in known-safe list
#   - HIGH finding: /tmp missing sticky bit (allows any user to delete others' files)
#
# All changes are reverted automatically on exit.
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
# Cleanup
# ---------------------------------------------------------------------------
HOSTS_ORIG_MODE=""
TMP_SUID_BINARY=""
TMP_ORIG_MODE=""

cleanup() {
    echo ""
    echo "[*] Cleaning up permission changes..."

    # Restore /etc/hosts permissions
    if [ -n "$HOSTS_ORIG_MODE" ]; then
        chmod "$HOSTS_ORIG_MODE" /etc/hosts
        echo "[+] /etc/hosts permissions restored to $HOSTS_ORIG_MODE"
    fi

    # Remove the SUID demo binary
    if [ -n "$TMP_SUID_BINARY" ] && [ -f "$TMP_SUID_BINARY" ]; then
        rm -f "$TMP_SUID_BINARY"
        echo "[+] SUID demo binary removed: $TMP_SUID_BINARY"
    fi

    # Restore /tmp sticky bit
    if [ -n "$TMP_ORIG_MODE" ]; then
        chmod "$TMP_ORIG_MODE" /tmp
        echo "[+] /tmp permissions restored to $TMP_ORIG_MODE"
    fi

    echo "[+] Cleanup complete"
}
trap cleanup EXIT

section_header "LSIM DEMO: Dangerous File Permissions Detection"

# ---------------------------------------------------------------------------
# Demo 1: World-writable file in /etc/ (critical directory)
#         Triggers: CRITICAL (world-writable file in critical dir)
# ---------------------------------------------------------------------------
section_header "DEMO 1/3: World-writable file in /etc/  |  Expected: CRITICAL"


HOSTS_ORIG_MODE=$(stat -c "%a" /etc/hosts)
echo "[*] Setting /etc/hosts world-writable (chmod o+w)..."
chmod o+w /etc/hosts
echo "[+] /etc/hosts is now world-writable"
echo ""
echo "    Permissions now: $(stat -c '%A' /etc/hosts)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Restore immediately
chmod "$HOSTS_ORIG_MODE" /etc/hosts
HOSTS_ORIG_MODE=""

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 2: Unexpected SUID binary not in the known-safe list
#         Triggers: CRITICAL (unknown SUID binary found)
# ---------------------------------------------------------------------------
section_header "DEMO 2/3: Unexpected SUID binary  |  Expected: CRITICAL"


TMP_SUID_BINARY="/usr/local/bin/lsim_demo_suid"
echo "[*] Copying /bin/ls to $TMP_SUID_BINARY and setting SUID bit..."
cp /bin/ls "$TMP_SUID_BINARY"
chmod u+s "$TMP_SUID_BINARY"
echo "[+] SUID binary created: $TMP_SUID_BINARY"
echo ""
echo "    Permissions: $(stat -c '%A' "$TMP_SUID_BINARY")"
echo ""

echo "[*] Running LSIM scan (the find command may take ~30s to scan the filesystem)..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Remove the SUID binary
rm -f "$TMP_SUID_BINARY"
TMP_SUID_BINARY=""

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 3: /tmp missing the sticky bit
#         Triggers: HIGH (/tmp sticky bit missing)
#
#  The sticky bit on /tmp (mode 1777) ensures only the file owner can delete
#  their own files. Without it, any user can delete any other user's temp files.
# ---------------------------------------------------------------------------
section_header "DEMO 3/3: /tmp missing sticky bit  |  Expected: HIGH"


TMP_ORIG_MODE=$(stat -c "%a" /tmp)
echo "[*] Removing sticky bit from /tmp (chmod 777)..."
echo "    Current mode: $TMP_ORIG_MODE"
chmod 777 /tmp
echo "[+] /tmp is now 777 (sticky bit removed)"
echo ""
echo "    Permissions now: $(stat -c '%A' /tmp)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Restore /tmp immediately
chmod "$TMP_ORIG_MODE" /tmp
TMP_ORIG_MODE=""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ Permissions demo complete."
echo ""
