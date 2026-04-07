#!/usr/bin/env bash
# =============================================================================
# LSIM Demo: User Account Security Threats
#
# Demonstrates:
#   - CRITICAL finding: user account with UID 0 (root-equivalent)
#   - HIGH finding: user account with no password set
#   - HIGH finding: NOPASSWD:ALL in sudoers
#   - MEDIUM finding: repeated failed SSH login attempts in auth.log
#
# Creates a temporary test user and sudoers file, restores on exit.
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

DEMO_USER="lsim_demo_user"
DEMO_SUDOERS_FILE="/etc/sudoers.d/lsim_demo"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[*] Cleaning up demo user and sudoers entry..."

    # Remove demo user if it exists
    if id "$DEMO_USER" &>/dev/null; then
        userdel -rf "$DEMO_USER" 2>/dev/null || true
        echo "[+] User '$DEMO_USER' removed"
    fi

    # Remove the UID-0 entry we injected (if any)
    # We modify /etc/passwd directly for the UID-0 demo — restore from backup
    if [ -n "${PASSWD_BACKUP:-}" ] && [ -f "$PASSWD_BACKUP" ]; then
        cp "$PASSWD_BACKUP" /etc/passwd
        rm -f "$PASSWD_BACKUP"
        echo "[+] /etc/passwd restored"
    fi

    # Remove demo shadow entry backup
    if [ -n "${SHADOW_BACKUP:-}" ] && [ -f "$SHADOW_BACKUP" ]; then
        cp "$SHADOW_BACKUP" /etc/shadow
        rm -f "$SHADOW_BACKUP"
        echo "[+] /etc/shadow restored"
    fi

    # Remove sudoers demo file
    rm -f "$DEMO_SUDOERS_FILE"
    echo "[+] Sudoers demo entry removed"

    echo "[+] Cleanup complete"
}
trap cleanup EXIT

section_header "LSIM DEMO: User Account Security Threats"

# ---------------------------------------------------------------------------
# Setup: Create a normal test user to use across demos
# ---------------------------------------------------------------------------
echo ""
echo "[*] Creating test user '$DEMO_USER'..."
useradd -m -s /bin/bash "$DEMO_USER" 2>/dev/null || true
echo "[+] User '$DEMO_USER' created"

# ---------------------------------------------------------------------------
# Demo 1: User with no password set (empty shadow hash)
#         Triggers: HIGH (empty password)
# ---------------------------------------------------------------------------
section_header "DEMO 1/4: User with no password  |  Expected: HIGH"


SHADOW_BACKUP=$(mktemp /tmp/shadow_backup.XXXXXX)
cp /etc/shadow "$SHADOW_BACKUP"

echo "[*] Removing password hash for '$DEMO_USER' in /etc/shadow..."
# Replace the hash field (field 2) with empty string for our test user
sed -i "s|^${DEMO_USER}:[^:]*:|${DEMO_USER}::|" /etc/shadow
echo "[+] Password hash cleared for '$DEMO_USER'"
echo ""
echo "    Shadow entry now:"
grep "^${DEMO_USER}:" /etc/shadow
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Restore shadow before next demo
cp "$SHADOW_BACKUP" /etc/shadow
SHADOW_BACKUP=""

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 2: NOPASSWD:ALL in sudoers
#         Triggers: HIGH (NOPASSWD sudoers entry)
# ---------------------------------------------------------------------------
section_header "DEMO 2/4: NOPASSWD:ALL sudoers entry  |  Expected: HIGH"
echo ""

echo "[*] Writing dangerous sudoers entry to $DEMO_SUDOERS_FILE..."
echo "${DEMO_USER} ALL=(ALL) NOPASSWD:ALL" > "$DEMO_SUDOERS_FILE"
chmod 440 "$DEMO_SUDOERS_FILE"
echo "[+] Sudoers entry created:"
cat "$DEMO_SUDOERS_FILE"
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Remove for next demo
rm -f "$DEMO_SUDOERS_FILE"

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 3: UID-0 account that is not root (root-equivalent backdoor account)
#         Triggers: CRITICAL (unauthorized root-equivalent account)
# ---------------------------------------------------------------------------
section_header "DEMO 3/4: Non-root account with UID 0  |  Expected: CRITICAL"


PASSWD_BACKUP=$(mktemp /tmp/passwd_backup.XXXXXX)
cp /etc/passwd "$PASSWD_BACKUP"

echo "[*] Changing UID of '$DEMO_USER' to 0 in /etc/passwd..."
# Replace uid field (field 3) with 0 for our test user
sed -i "s|^${DEMO_USER}:\([^:]*\):\([^:]*\):|${DEMO_USER}:\1:0:|" /etc/passwd
echo "[+] UID set to 0 for '$DEMO_USER'"
echo ""
echo "    /etc/passwd entry now:"
grep "^${DEMO_USER}:" /etc/passwd
echo ""

echo "[*] Running LSIM scan..."
echo ""
python3 "$LSIM" --scan --no-respond || true

# Restore /etc/passwd
cp "$PASSWD_BACKUP" /etc/passwd
PASSWD_BACKUP=""

wait_for_enter

# ---------------------------------------------------------------------------
# Demo 4: Simulate repeated failed logins in auth.log
#         Triggers: MEDIUM (brute-force indicator)
# ---------------------------------------------------------------------------
section_header "DEMO 4/4: Brute-force attack in auth.log  |  Expected: MEDIUM"


AUTH_LOG="/var/log/auth.log"
INJECTED_LINES=()

if [ -w "$AUTH_LOG" ] || [ -w "$(dirname "$AUTH_LOG")" ]; then
    TIMESTAMP=$(date "+%b %e %H:%M:%S")
    HOSTNAME=$(hostname)

    echo "[*] Injecting 15 failed login attempts into $AUTH_LOG..."
    for i in $(seq 1 15); do
        LINE="$TIMESTAMP $HOSTNAME sshd[99999]: Failed password for $DEMO_USER from 10.0.0.99 port $((50000 + i)) ssh2"
        echo "$LINE" >> "$AUTH_LOG"
        INJECTED_LINES+=("$LINE")
    done
    echo "[+] 15 failed login entries injected"
    echo ""

    echo "[*] Running LSIM scan..."
    echo ""
    python3 "$LSIM" --scan --no-respond || true

    # Remove injected lines
    echo ""
    echo "[*] Removing injected auth.log entries..."
    for line in "${INJECTED_LINES[@]}"; do
        # Escape special chars for grep -F
        grep -vF "$line" "$AUTH_LOG" > "${AUTH_LOG}.tmp" && mv "${AUTH_LOG}.tmp" "$AUTH_LOG" || true
    done
    echo "[+] Auth.log cleaned"
else
    echo "[!] Cannot write to $AUTH_LOG — skipping this demo"
    echo "    (Run as root with write access to /var/log/auth.log)"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "  ✓ User Risks demo complete."
echo ""
