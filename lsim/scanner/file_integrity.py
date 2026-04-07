"""
File Integrity Scanner — thin wrapper around baseline.py.
"""

from lsim.baseline import compare_to_baseline, load_baseline
from lsim.config import SEVERITY_INFO
from lsim.finding import Finding


class FileIntegrityScanner:
    def scan(self) -> list:
        try:
            baseline = load_baseline()
        except FileNotFoundError as exc:
            return [Finding(
                category="File Integrity",
                severity=SEVERITY_INFO,
                title="No baseline established",
                detail=str(exc),
                recommendation="Run: sudo python3 lsim.py --baseline",
            )]
        except ValueError as exc:
            return [Finding(
                category="File Integrity",
                severity=SEVERITY_INFO,
                title="Baseline schema error",
                detail=str(exc),
                recommendation="Re-create baseline: sudo python3 lsim.py --baseline",
            )]

        return compare_to_baseline(baseline)
