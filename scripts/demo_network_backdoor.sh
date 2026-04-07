#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: Network Threat Detection
#
# Demonstrates:
#   - HIGH finding: process listening on suspicious port 4444 (Metasploit default)
#   - HIGH finding: process listening on suspicious port 9999 (backdoor port)
#   - MEDIUM finding: unexpected service listening on 0.0.0.0 (non-well-known port)
#   - HIGH finding: raw socket open (packet sniffing/crafting capability)
#
# Uses Python's socket and http.server modules — no external tools needed.
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
BGPIDS=()
TMP_LISTENER_SCRIPT=""
TMP_RAW_SCRIPT=""

cleanup() {
    echo ""
    echo "[*] Cleaning up listeners and temp files..."
    for pid in "${BGPIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    [ -n "$TMP_LISTENER_SCRIPT" ] && rm -f "$TMP_LISTENER_SCRIPT"
    [ -n "$TMP_RAW_SCRIPT"      ] && rm -f "$TMP_RAW_SCRIPT"
    echo "[+] All listeners stopped"
}
trap cleanup EXIT

section_header "LSIM DEMO: Network Threat Detection"

# ---------------------------------------------------------------------------
# Demo 1: Listener on suspicious port 4444 (Metasploit default)
#         Triggers: HIGH (suspicious port) from both process + network scanners
# ---------------------------------------------------------------------------
section_header "DEMO 1/4: Backdoor listener on port 4444  |  Expected: HIGH"


TMP_LISTENER_SCRIPT=$(mktemp /tmp/lsim_listener.XXXXXX.py)
cat > "$TMP_LISTENER_SCRIPT" << 'EOF'
import socket, time, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = int(sys.argv[1])
s.bind(('0.0.0.0', port))
s.listen(1)
time.sleep(120)
s.close()
EOF

echo "[*] Opening listener on port 4444..."
python3 "$TMP_LISTENER_SCRIPT" 4444 &
L4444_PID=$!
BGPIDS+=("$L4444_PID")
sleep 0.5  # Give it a moment to bind
echo "[+] Port 4444 now listening (PID $L4444_PID)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$L4444_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$L4444_PID}")

# ---------------------------------------------------------------------------
# Demo 2: Listener on port 9999 (common backdoor port)
#         Triggers: HIGH (suspicious port)
# ---------------------------------------------------------------------------
section_header "DEMO 2/4: Backdoor listener on port 9999  |  Expected: HIGH"


echo "[*] Opening listener on port 9999..."
python3 "$TMP_LISTENER_SCRIPT" 9999 &
L9999_PID=$!
BGPIDS+=("$L9999_PID")
sleep 0.5
echo "[+] Port 9999 now listening (PID $L9999_PID)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$L9999_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$L9999_PID}")

# ---------------------------------------------------------------------------
# Demo 3: Unexpected service on non-standard port (not in well-known list)
#         Triggers: MEDIUM (unexpected listener on 0.0.0.0)
# ---------------------------------------------------------------------------
section_header "DEMO 3/4: Unexpected listener on port 7331  |  Expected: MEDIUM"


echo "[*] Opening unexpected listener on port 7331..."
python3 "$TMP_LISTENER_SCRIPT" 7331 &
L7331_PID=$!
BGPIDS+=("$L7331_PID")
sleep 0.5
echo "[+] Port 7331 now listening (PID $L7331_PID)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$L7331_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$L7331_PID}")

# ---------------------------------------------------------------------------
# Demo 4: Raw socket (requires root — packet sniffer capability)
#         Triggers: HIGH (raw socket)
# ---------------------------------------------------------------------------
section_header "DEMO 4/4: Raw socket open  |  Expected: HIGH (packet sniffer capability)"


TMP_RAW_SCRIPT=$(mktemp /tmp/lsim_raw_socket.XXXXXX.py)
cat > "$TMP_RAW_SCRIPT" << 'EOF'
import socket, time
# Open a raw socket — this is what packet sniffers and network tools use.
# Requires root. We hold it open so LSIM can detect it.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    time.sleep(120)
    s.close()
except PermissionError:
    print("Permission denied — must run as root")
EOF

echo "[*] Opening a raw socket (simulates packet sniffer/injector)..."
python3 "$TMP_RAW_SCRIPT" &
RAW_PID=$!
BGPIDS+=("$RAW_PID")
sleep 0.5
echo "[+] Raw socket open (PID $RAW_PID)"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

kill "$RAW_PID" 2>/dev/null || true
BGPIDS=("${BGPIDS[@]/$RAW_PID}")

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ Network Backdoor demo complete."
echo ""
