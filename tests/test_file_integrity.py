"""
Tests for lsim/scanner/file_integrity.py and lsim/baseline.py
"""

import json
import os
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, mock_open, patch

from lsim.baseline import compare_to_baseline, create_baseline, hash_file
from lsim.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFO
from lsim.scanner.file_integrity import FileIntegrityScanner


class TestHashFile(unittest.TestCase):
    def test_hashes_real_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = f.name
        try:
            result = hash_file(path)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 64)  # SHA-256 hex digest
        finally:
            os.unlink(path)

    def test_returns_none_on_missing_file(self):
        result = hash_file("/nonexistent/path/file.txt")
        self.assertIsNone(result)

    def test_returns_none_on_permission_error(self):
        with patch("builtins.open", side_effect=PermissionError):
            result = hash_file("/etc/shadow")
        self.assertIsNone(result)

    def test_hash_changes_on_content_change(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"original content")
            path = f.name
        try:
            h1 = hash_file(path)
            with open(path, "wb") as f:
                f.write(b"modified content")
            h2 = hash_file(path)
            self.assertNotEqual(h1, h2)
        finally:
            os.unlink(path)


class TestCompareToBaseline(unittest.TestCase):
    def _make_baseline(self, filepath, content=b"original"):
        """Helper: create a baseline dict for a single temp file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(content)
            path = f.name

        import hashlib
        h = hashlib.sha256(content).hexdigest()
        st = os.stat(path)
        baseline = {
            "schema_version": 1,
            "created_at": "2024-01-01T00:00:00+00:00",
            "updated_at": "2024-01-01T00:00:00+00:00",
            "hostname": "test-host",
            "files": {
                path: {
                    "hash": h,
                    "size": len(content),
                    "mtime": st.st_mtime,
                    "permissions": oct(stat.S_IMODE(st.st_mode)),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                }
            },
        }
        return path, baseline

    def test_no_findings_on_unchanged_file(self):
        path, baseline = self._make_baseline("/tmp/test")
        try:
            findings = compare_to_baseline(baseline)
            self.assertEqual(findings, [])
        finally:
            os.unlink(path)

    def test_critical_finding_on_modified_file(self):
        path, baseline = self._make_baseline("/tmp/test")
        try:
            # Modify the file
            with open(path, "wb") as f:
                f.write(b"tampered content")
            findings = compare_to_baseline(baseline)
            self.assertTrue(any(f.severity == SEVERITY_CRITICAL for f in findings))
            self.assertTrue(any("modified" in f.title.lower() for f in findings))
        finally:
            os.unlink(path)

    def test_critical_finding_on_deleted_file(self):
        path, baseline = self._make_baseline("/tmp/test")
        os.unlink(path)  # Delete the file
        findings = compare_to_baseline(baseline)
        self.assertTrue(any(f.severity == SEVERITY_CRITICAL for f in findings))
        self.assertTrue(any("deleted" in f.title.lower() for f in findings))

    def test_high_finding_on_permission_change(self):
        path, baseline = self._make_baseline("/tmp/test")
        try:
            # Store original mode and change permissions
            original_mode = baseline["files"][path]["permissions"]
            os.chmod(path, 0o777)
            findings = compare_to_baseline(baseline)
            perm_findings = [f for f in findings if "permission" in f.title.lower()]
            self.assertTrue(len(perm_findings) > 0)
            self.assertEqual(perm_findings[0].severity, SEVERITY_HIGH)
        finally:
            os.unlink(path)

    def test_empty_baseline_yields_no_findings(self):
        baseline = {
            "schema_version": 1,
            "files": {},
        }
        findings = compare_to_baseline(baseline)
        self.assertEqual(findings, [])


class TestFileIntegrityScanner(unittest.TestCase):
    def test_no_baseline_returns_info_finding(self):
        with patch("lsim.scanner.file_integrity.load_baseline",
                   side_effect=FileNotFoundError("no baseline")):
            scanner = FileIntegrityScanner()
            findings = scanner.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_INFO)
        self.assertIn("baseline", findings[0].title.lower())

    def test_delegates_to_compare_to_baseline(self):
        fake_finding = MagicMock()
        fake_baseline = {"schema_version": 1, "files": {}}
        with patch("lsim.scanner.file_integrity.load_baseline", return_value=fake_baseline), \
             patch("lsim.scanner.file_integrity.compare_to_baseline", return_value=[fake_finding]):
            scanner = FileIntegrityScanner()
            findings = scanner.scan()
        self.assertEqual(findings, [fake_finding])

    def test_schema_error_returns_info_finding(self):
        with patch("lsim.scanner.file_integrity.load_baseline",
                   side_effect=ValueError("schema mismatch")):
            scanner = FileIntegrityScanner()
            findings = scanner.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, SEVERITY_INFO)


if __name__ == "__main__":
    unittest.main()
