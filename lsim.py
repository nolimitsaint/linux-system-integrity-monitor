#!/usr/bin/env python3
"""
LSIM — Linux System Integrity Monitor
Entry point / CLI

Usage: sudo python3 lsim.py [OPTIONS]
"""

import argparse
import json
import os
import signal
import sys
import time

# ---------------------------------------------------------------------------
# Root check — must happen before any module imports that touch /var/lib/lsim
# ---------------------------------------------------------------------------
if os.geteuid() != 0:
    print("[-] LSIM must be run as root: sudo python3 lsim.py --scan", file=sys.stderr)
    sys.exit(1)


from lsim.auditor.firewall import FirewallAuditor
from lsim.auditor.packages import PackagesAuditor
from lsim.auditor.permissions import PermissionsAuditor
from lsim.baseline import create_baseline, load_baseline, save_baseline
from lsim.config import SEVERITY_CRITICAL, SEVERITY_HIGH, WATCHED_FILES
from lsim.finding import Finding, determine_state
from lsim.logger import LSIMLogger, get_logger
from lsim.reporter import Reporter
from lsim.responder.lockdown import LockdownManager
from lsim.responder.process_killer import ProcessKiller
from lsim.responder.user_disabler import UserDisabler
from lsim.scanner.file_integrity import FileIntegrityScanner
from lsim.scanner.network_scanner import NetworkScanner
from lsim.scanner.process_scanner import ProcessScanner
from lsim.scanner.user_scanner import UserScanner

_log = get_logger()


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lsim",
        description="Linux System Integrity Monitor — detect and respond to system threats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 lsim.py --baseline          Create integrity baseline\n"
            "  sudo python3 lsim.py --scan              Run a full scan\n"
            "  sudo python3 lsim.py --scan --no-respond Scan without automated response\n"
            "  sudo python3 lsim.py --daemon --interval 300  Daemon mode, scan every 5 min\n"
            "  sudo python3 lsim.py --unlock            Release network lockdown\n"
        ),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true", default=True,
                      help="Run a full one-time scan (default)")
    mode.add_argument("--baseline", action="store_true",
                      help="Create or update the integrity baseline")
    mode.add_argument("--daemon", action="store_true",
                      help="Run continuously, re-scanning every --interval seconds")
    mode.add_argument("--report", action="store_true",
                      help="Show the last saved report from logs/")
    mode.add_argument("--lockdown", action="store_true",
                      help="Manually activate network lockdown")
    mode.add_argument("--unlock", action="store_true",
                      help="Manually release network lockdown")

    p.add_argument("--interval", type=int, default=300, metavar="N",
                   help="Daemon re-scan interval in seconds (default: 300)")
    p.add_argument("--no-respond", action="store_true",
                   help="Scan only; do not take automated response actions")
    p.add_argument("--verbose", action="store_true",
                   help="Show INFO-level findings in output")
    p.add_argument("--json", action="store_true",
                   help="Output results as JSON (for scripting)")
    p.add_argument("--yes", action="store_true",
                   help="Skip confirmation prompts")
    return p


# ---------------------------------------------------------------------------
# Baseline creation
# ---------------------------------------------------------------------------

def cmd_baseline(args):
    print("[*] Creating integrity baseline...")
    print(f"    Watching {len(WATCHED_FILES)} paths")

    baseline = create_baseline(WATCHED_FILES)
    file_count = len(baseline["files"])
    print(f"    Hashed {file_count} files")

    path = save_baseline(baseline)
    print(f"[+] Baseline saved to: {path}")
    print("[+] Run 'sudo python3 lsim.py --scan' to check for changes.")


# ---------------------------------------------------------------------------
# Full scan
# ---------------------------------------------------------------------------

def run_scan(args) -> int:
    """
    Execute all scanners and auditors, collect findings, determine state,
    optionally respond, report, and log.

    Returns: 0 (SECURE), 1 (AT_RISK), 2 (LOCKDOWN)
    """
    findings: list = []
    reporter = Reporter()
    logger_obj = LSIMLogger()

    print("[*] Scanning file integrity...")
    findings += FileIntegrityScanner().scan()

    print("[*] Scanning running processes...")
    findings += ProcessScanner().scan()

    print("[*] Scanning user accounts...")
    findings += UserScanner().scan()

    print("[*] Scanning network connections...")
    findings += NetworkScanner().scan()

    print("[*] Auditing firewall...")
    findings += FirewallAuditor().audit()

    print("[*] Auditing file permissions...")
    findings += PermissionsAuditor().audit()

    print("[*] Auditing packages...")
    findings += PackagesAuditor().audit()

    state = determine_state(findings)
    actions_taken: list = []

    if state == "LOCKDOWN" and not args.no_respond:
        actions_taken = respond_to_lockdown(findings, logger_obj)

    reporter.display(
        state=state,
        findings=findings,
        actions_taken=actions_taken,
        verbose=args.verbose,
        as_json=args.json,
    )

    if state == "LOCKDOWN" and not args.json:
        reporter.print_lockdown_warning()

    logger_obj.log_scan_result(state, findings, actions_taken)

    return {"SECURE": 0, "AT_RISK": 1, "LOCKDOWN": 2}.get(state, 1)


# ---------------------------------------------------------------------------
# Automated response
# ---------------------------------------------------------------------------

def respond_to_lockdown(findings: list, logger_obj: LSIMLogger) -> list:
    """Execute automated responses for LOCKDOWN-triggering findings."""
    actions = []
    killer = ProcessKiller()
    disabler = UserDisabler()
    lockdown = LockdownManager()

    for finding in findings:
        if (finding.severity == SEVERITY_CRITICAL
                and finding.pid is not None
                and finding.auto_remediate):
            success = killer.kill_process(finding.pid, finding.title)
            symbol = "✓" if success else "✗"
            msg = f"{symbol} Kill PID {finding.pid}: {finding.title}"
            actions.append(msg)
            logger_obj.log_action("kill_process", str(finding.pid), finding.title, success)

        if (finding.severity in (SEVERITY_CRITICAL, SEVERITY_HIGH)
                and finding.username is not None
                and finding.auto_remediate):
            success = disabler.disable_user(finding.username, finding.title)
            symbol = "✓" if success else "✗"
            msg = f"{symbol} Lock user '{finding.username}': {finding.title}"
            actions.append(msg)
            logger_obj.log_action("disable_user", finding.username, finding.title, success)

    if not lockdown.is_locked_down():
        critical_count = sum(1 for f in findings if f.severity == SEVERITY_CRITICAL)
        success = lockdown.activate_lockdown(reason=f"{critical_count} critical finding(s) detected")
        symbol = "✓" if success else "✗"
        actions.append(f"{symbol} Network lockdown activated")
        logger_obj.log_lockdown(activated=True, reason="Automated response to LOCKDOWN state")
    else:
        actions.append("[already active] Network lockdown")

    return actions


# ---------------------------------------------------------------------------
# Report (last log)
# ---------------------------------------------------------------------------

def cmd_report(_args):
    from lsim.config import LOG_FILE_JSONL
    if not os.path.isfile(LOG_FILE_JSONL):
        print(f"[-] No log found at {LOG_FILE_JSONL}. Run a scan first.")
        return
    try:
        with open(LOG_FILE_JSONL) as fh:
            lines = fh.readlines()
        if not lines:
            print("[-] Log file is empty.")
            return
        last = json.loads(lines[-1])
        print(json.dumps(last, indent=2))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] Error reading log: {exc}")


# ---------------------------------------------------------------------------
# Daemon mode
# ---------------------------------------------------------------------------

_daemon_running = True


def _handle_sigterm(signum, frame):
    global _daemon_running
    print("\n[*] SIGTERM received — stopping daemon")
    _daemon_running = False


def cmd_daemon(args):
    signal.signal(signal.SIGTERM, _handle_sigterm)
    print(f"[*] Daemon mode — scanning every {args.interval} seconds (Ctrl+C to stop)")
    try:
        while _daemon_running:
            print(f"\n[*] Starting scan at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            run_scan(args)
            if _daemon_running:
                print(f"[*] Next scan in {args.interval} seconds...")
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Daemon stopped by user")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Resolve the default --scan vs explicit mode flags
    # argparse mutually_exclusive_group: if user sets --baseline etc., --scan is False
    explicit_modes = (args.baseline, args.daemon, args.report, args.lockdown, args.unlock)
    if any(explicit_modes):
        args.scan = False

    if args.baseline:
        cmd_baseline(args)
        sys.exit(0)

    if args.lockdown:
        mgr = LockdownManager()
        if mgr.is_locked_down():
            print("[!] System is already in lockdown.")
        else:
            print("[*] Manually activating network lockdown...")
            ok = mgr.activate_lockdown(reason="Manual --lockdown flag")
            lsim_logger = LSIMLogger()
            lsim_logger.log_lockdown(activated=True, reason="Manual activation via --lockdown")
            print("[+] Lockdown activated." if ok else "[-] Lockdown failed — check logs.")
        sys.exit(0 if mgr.is_locked_down() else 1)

    if args.unlock:
        mgr = LockdownManager()
        if not mgr.is_locked_down():
            print("[!] System is not in lockdown.")
        else:
            print("[*] Releasing network lockdown...")
            ok = mgr.deactivate_lockdown()
            lsim_logger = LSIMLogger()
            lsim_logger.log_lockdown(activated=False, reason="Manual release via --unlock")
            print("[+] Lockdown released." if ok else "[-] Unlock failed — check logs.")
        sys.exit(0)

    if args.report:
        cmd_report(args)
        sys.exit(0)

    if args.daemon:
        cmd_daemon(args)
        sys.exit(0)

    # Default: --scan
    exit_code = run_scan(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
