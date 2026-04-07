#!/usr/bin/env bash
# =============================================================================
# lib_common.sh — shared helpers sourced by all LSIM demo scripts
# Source this file, do not execute it directly.
# =============================================================================

# ---------------------------------------------------------------------------
# Check that psutil is available to the ROOT Python interpreter.
# If missing, prompt the user to install it and offer to do so automatically.
# Call this near the top of any script that invokes lsim.py --scan.
# ---------------------------------------------------------------------------
check_psutil() {
    if python3 -c "import psutil" 2>/dev/null; then
        return 0  # already installed, nothing to do
    fi

    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║  WARNING: psutil is not installed for root Python        ║"
    echo "  ║                                                          ║"
    echo "  ║  The process and network scanners will be skipped,       ║"
    echo "  ║  meaning LSIM won't detect suspicious processes or       ║"
    echo "  ║  network connections during this demo.                   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
    read -r -p "  Install psutil now? [Y/n] " answer
    if [[ ! "$answer" =~ ^[Nn]$ ]]; then
        echo ""
        echo "[*] Installing psutil..."
        if pip3 install --break-system-packages psutil 2>&1 | tail -2; then
            echo "[+] psutil installed successfully"
            echo ""
            return 0
        else
            echo "[-] Installation failed. Try manually: sudo pip3 install --break-system-packages psutil"
            echo ""
            read -r -p "  Continue demo anyway (process/network findings will be missing)? [y/N] " cont
            if [[ ! "$cont" =~ ^[Yy]$ ]]; then
                echo "[*] Aborted."
                exit 1
            fi
        fi
    else
        echo ""
        echo "[!] Skipping install. Process and network scanner results will be missing."
        echo ""
        read -r -p "  Continue anyway? [y/N] " cont
        if [[ ! "$cont" =~ ^[Yy]$ ]]; then
            echo "[*] Aborted."
            exit 1
        fi
    fi
}

# ---------------------------------------------------------------------------
# Clear the screen and print a header bar for a new demo section.
# Usage: section_header "DEMO 1: File Integrity Detection"
# ---------------------------------------------------------------------------
section_header() {
    clear
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    printf  "  │  %-55s  │\n" "$1"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo ""
}
