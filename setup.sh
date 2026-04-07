#!/usr/bin/env bash
# setup.sh — Install LSIM on Ubuntu 24.04
# Usage: sudo bash setup.sh

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run as root: sudo bash setup.sh"
    exit 1
fi

echo "[*] Linux System Integrity Monitor — Setup"
echo "    ======================================="

# ---------------------------------------------------------------------------
# Check Python version (requires 3.10+)
# ---------------------------------------------------------------------------
echo "[*] Checking Python version..."
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    echo "[-] python3 not found. Install with: sudo apt install python3"
    exit 1
fi

PYVER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMAJ=$($PYTHON -c "import sys; print(sys.version_info.major)")
PYMIN=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 10 ]; }; then
    echo "[-] Python 3.10+ required. Found: $PYVER"
    exit 1
fi
echo "[+] Python $PYVER — OK"

# ---------------------------------------------------------------------------
# Create log and state directories
# ---------------------------------------------------------------------------
echo "[*] Creating directories..."
mkdir -p /var/log/lsim
chmod 750 /var/log/lsim
mkdir -p /var/lib/lsim
chmod 700 /var/lib/lsim
echo "[+] /var/log/lsim and /var/lib/lsim created"

# ---------------------------------------------------------------------------
# Check for python-apt (system package — warn if missing, not fatal)
# ---------------------------------------------------------------------------
echo "[*] Checking for python-apt..."
if $PYTHON -c "import apt" 2>/dev/null; then
    echo "[+] python-apt — available"
else
    echo "[!] python-apt not found. Install with: sudo apt install python3-apt"
    echo "    (Packages auditor will fall back to 'apt list --upgradable')"
fi

# ---------------------------------------------------------------------------
# Install Python dependencies
# ---------------------------------------------------------------------------
echo "[*] Installing Python dependencies from requirements.txt..."
pip3 install -q -r "$(dirname "$0")/requirements.txt"
echo "[+] Python dependencies installed"

# ---------------------------------------------------------------------------
# Make lsim.py executable
# ---------------------------------------------------------------------------
LSIM_PATH="$(dirname "$0")/lsim.py"
if [ -f "$LSIM_PATH" ]; then
    chmod +x "$LSIM_PATH"
    echo "[+] lsim.py is executable"
fi

# ---------------------------------------------------------------------------
# Optional symlink to /usr/local/bin
# ---------------------------------------------------------------------------
read -r -p "[?] Create symlink at /usr/local/bin/lsim? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    ABSPATH="$(realpath "$LSIM_PATH")"
    ln -sf "$ABSPATH" /usr/local/bin/lsim
    echo "[+] Symlink created: /usr/local/bin/lsim -> $ABSPATH"
fi

echo ""
echo "[✓] LSIM installed successfully!"
echo ""
echo "    Next steps:"
echo "      1. Create integrity baseline:  sudo python3 lsim.py --baseline"
echo "      2. Run a full scan:            sudo python3 lsim.py --scan"
echo "      3. Run tests (no root):        pytest tests/ -v"
echo ""
