#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Suspicious Process Detection
#
# Demonstrates:
#   - CRITICAL finding: process executing from /tmp/ (suspicious path)
#   - HIGH finding: process with suspicious name ("nc")
#   - HIGH finding: process with LD_PRELOAD set in environment
#   - HIGH finding: process running from a deleted executable
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
TMP_LD_BINARY=""
TMP_PRELOAD_LIB=""
TMP_DELETED_BINARY=""
BGPIDS=()

cleanup() {
    echo ""
    echo "[*] Cleaning up background processes and temp files..."
    for pid in "${BGPIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    [ -n "$TMP_NC"            ] && rm -f "$TMP_NC"
    [ -n "$TMP_LD_BINARY"     ] && rm -f "$TMP_LD_BINARY"
    [ -n "$TMP_PRELOAD_LIB"   ] && rm -f "$TMP_PRELOAD_LIB"
    # TMP_DELETED_BINARY is intentionally deleted during the demo
    echo "[+] Cleanup complete"
}
trap cleanup EXIT

section_header "LSIM DEMO: Suspicious Process Detection"

# ---------------------------------------------------------------------------
# Demo 1: Process executing from /tmp/ with suspicious name
#         Triggers: CRITICAL (suspicious path) + HIGH (suspicious name)
# ---------------------------------------------------------------------------
section_header "DEMO 1/3: Process in /tmp/ with name 'nc'  |  Expected: CRITICAL + HIGH"


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
# Demo 2: Process with LD_PRELOAD in environment
#         Triggers: HIGH (LD_PRELOAD injection)
# ---------------------------------------------------------------------------
section_header "DEMO 2/3: Process with LD_PRELOAD set  |  Expected: HIGH"


# Create a minimal (harmless) shared library source
TMP_PRELOAD_LIB="/tmp/lsim_demo_hook.so"
TMP_C_SRC="/tmp/lsim_demo_hook.c"

cat > "$TMP_C_SRC" << 'EOF'
// Harmless demo shared library for LSIM LD_PRELOAD detection demo
void __attribute__((constructor)) lsim_demo_init(void) {}
EOF

echo "[*] Compiling a harmless demo shared library..."
if command -v gcc &>/dev/null; then
    gcc -shared -fPIC -o "$TMP_PRELOAD_LIB" "$TMP_C_SRC" 2>/dev/null
    rm -f "$TMP_C_SRC"
    echo "[+] Library created at $TMP_PRELOAD_LIB"

    TMP_LD_BINARY="/tmp/lsim_demo_sleep"
    cp /bin/sleep "$TMP_LD_BINARY"

    echo "[*] Launching process with LD_PRELOAD=$TMP_PRELOAD_LIB..."
    env LD_PRELOAD="$TMP_PRELOAD_LIB" "$TMP_LD_BINARY" 120 &
    LD_PID=$!
    BGPIDS+=("$LD_PID")
    echo "[+] Launched with LD_PRELOAD (PID $LD_PID)"
    echo ""

    echo "[*] Running LSIM scan..."
    echo ""
    python3 "$LSIM" --scan --no-respond || true

    kill "$LD_PID" 2>/dev/null || true
    BGPIDS=("${BGPIDS[@]/$LD_PID}")
    rm -f "$TMP_PRELOAD_LIB" "$TMP_LD_BINARY"
    TMP_PRELOAD_LIB=""
    TMP_LD_BINARY=""
else
    echo "[!] gcc not found — skipping LD_PRELOAD demo (install: sudo apt install gcc)"
fi

# ---------------------------------------------------------------------------
# Demo 3: Process running from a deleted executable
#         Triggers: HIGH (deleted executable)
# ---------------------------------------------------------------------------
section_header "DEMO 3/3: Process running from a deleted binary  |  Expected: HIGH"


TMP_DELETED_BINARY="/tmp/lsim_demo_deleted"
cp /bin/sleep "$TMP_DELETED_BINARY"
chmod +x "$TMP_DELETED_BINARY"

echo "[*] Launching $TMP_DELETED_BINARY in background..."
"$TMP_DELETED_BINARY" 120 &
DEL_PID=$!
BGPIDS+=("$DEL_PID")
echo "[+] Running as PID $DEL_PID"

echo "[*] Deleting the binary while the process still runs..."
rm -f "$TMP_DELETED_BINARY"
TMP_DELETED_BINARY=""
echo "[+] Binary deleted — /proc/$DEL_PID/exe now points to '(deleted)'"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$DEL_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$DEL_PID}")

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ Suspicious Process demo complete."
echo ""
