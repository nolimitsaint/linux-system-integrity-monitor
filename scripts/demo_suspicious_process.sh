#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Suspicious Process Detection
#
# Demonstrates:
#   - CRITICAL finding: process executing from /tmp/ (suspicious path)
#   - HIGH finding: process with suspicious name ("nc")
#
# Uses only /bin/sleep as the harmless stand-in binary — nothing destructive.
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

check_psutil

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
TMP_NC=""
BGPIDS=()

cleanup() {
    echo ""
    echo "[*] Cleaning up background processes and temp files..."
    for pid in "${BGPIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    [ -n "$TMP_NC" ] && rm -f "$TMP_NC"
    echo "[+] Cleanup complete"
}
trap cleanup EXIT

section_header "LSIM DEMO: Suspicious Process Detection"

# ---------------------------------------------------------------------------
# Demo 1: Process executing from /tmp/ with suspicious name
#         Triggers: CRITICAL (suspicious path) + HIGH (suspicious name)
# ---------------------------------------------------------------------------
section_header "DEMO 1/1: Process in /tmp/ with name 'nc'  |  Expected: CRITICAL + HIGH"


TMP_NC="/tmp/nc"
echo "[*] Copying /bin/sleep to /tmp/nc..."
cp /bin/sleep "$TMP_NC"
chmod +x "$TMP_NC"

echo "[*] Running /tmp/nc in the background (sleeps 120s)..."
"$TMP_NC" 120 &
NC_PID=$!
BGPIDS+=("$NC_PID")
echo "[+] Launched /tmp/nc (PID $NC_PID)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$NC_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$NC_PID}")
rm -f "$TMP_NC"
TMP_NC=""

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ Suspicious Process demo complete."
echo ""
