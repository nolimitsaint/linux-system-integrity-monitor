#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Dangerous File Permissions Detection
#
# Demonstrates:
#   - CRITICAL finding: world-writable file in /etc/ (critical directory)
#   - CRITICAL finding: unexpected SUID binary not in known-safe list
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

cleanup() {
    echo ""
    echo "[*] Cleaning up permission changes..."

    if [ -n "$HOSTS_ORIG_MODE" ]; then
        chmod "$HOSTS_ORIG_MODE" /etc/hosts
        echo "[+] /etc/hosts permissions restored to $HOSTS_ORIG_MODE"
    fi

    if [ -n "$TMP_SUID_BINARY" ] && [ -f "$TMP_SUID_BINARY" ]; then
        rm -f "$TMP_SUID_BINARY"
        echo "[+] SUID demo binary removed: $TMP_SUID_BINARY"
    fi

    echo "[+] Cleanup complete"
}
trap cleanup EXIT

section_header "LSIM DEMO: Dangerous File Permissions Detection"

# ---------------------------------------------------------------------------
# Demo 1: World-writable file in /etc/ (critical directory)
#         Triggers: CRITICAL (world-writable file in critical dir)
# ---------------------------------------------------------------------------
section_header "DEMO 1/2: World-writable file in /etc/  |  Expected: CRITICAL"


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
section_header "DEMO 2/2: Unexpected SUID binary  |  Expected: CRITICAL"


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

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ Permissions demo complete."
echo ""
