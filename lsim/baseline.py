"""
Baseline snapshot management.

Stores SHA-256 hashes + metadata for watched files.
Persisted as JSON to BASELINE_FILE; compared on each scan to detect changes.
"""

import hashlib
import json
import os
import socket
import stat
import tempfile
from datetime import datetime, timezone
from typing import Optional

from lsim.config import (
    BASELINE_FILE,
    BASELINE_FILE_FALLBACK,
    HASH_ALGO,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    WATCHED_FILES,
)
from lsim.finding import Finding

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_file(filepath: str) -> Optional[str]:
    """
    Compute SHA-256 hash of a file, reading in 64 KB chunks.
    Returns None on PermissionError, IOError, or if the path is not a file.
    """
    try:
        h = hashlib.new(HASH_ALGO)
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, IOError, OSError):
        return None


def _file_metadata(filepath: str) -> dict:
    """Return a metadata dict for a file path. Returns partial dict on error."""
    meta = {
        "hash": None,
        "size": None,
        "mtime": None,
        "permissions": None,
        "uid": None,
        "gid": None,
    }
    try:
        st = os.stat(filepath)
        meta["size"] = st.st_size
        meta["mtime"] = st.st_mtime
        meta["permissions"] = oct(stat.S_IMODE(st.st_mode))
        meta["uid"] = st.st_uid
        meta["gid"] = st.st_gid
    except (PermissionError, IOError, OSError):
        pass
    meta["hash"] = hash_file(filepath)
    return meta


# ---------------------------------------------------------------------------
# Baseline creation
# ---------------------------------------------------------------------------

def create_baseline(paths: list = None) -> dict:
    """
    Walk each path in paths (defaults to WATCHED_FILES).
    - Files: hash + metadata directly.
    - Directories: walk and hash every file inside.
    Returns the baseline dict (not yet written to disk).
    """
    if paths is None:
        paths = WATCHED_FILES

    files: dict = {}

    for path in paths:
        if not os.path.exists(path):
            continue
        if os.path.isfile(path):
            files[path] = _file_metadata(path)
        elif os.path.isdir(path):
            for dirpath, _, filenames in os.walk(path):
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    if os.path.isfile(full):
                        files[full] = _file_metadata(full)

    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "hostname": socket.gethostname(),
        "files": files,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _resolve_path(path: str) -> str:
    """Try the given path; fall back to BASELINE_FILE_FALLBACK if not writable."""
    parent = os.path.dirname(path)
    if os.path.isdir(parent) and os.access(parent, os.W_OK):
        return path
    # Ensure fallback directory exists
    fallback_dir = os.path.dirname(BASELINE_FILE_FALLBACK)
    os.makedirs(fallback_dir, exist_ok=True)
    return BASELINE_FILE_FALLBACK


def save_baseline(baseline: dict, path: str = BASELINE_FILE) -> str:
    """
    Atomically write baseline JSON using a temp file + os.replace().
    Returns the path actually written to.
    """
    resolved = _resolve_path(path)
    parent = os.path.dirname(resolved)
    os.makedirs(parent, exist_ok=True)

    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()

    fd, tmp_path = tempfile.mkstemp(dir=parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(baseline, fh, indent=2)
        os.replace(tmp_path, resolved)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return resolved


def load_baseline(path: str = BASELINE_FILE) -> dict:
    """
    Load and return the baseline dict.
    Raises FileNotFoundError if baseline doesn't exist at path or fallback.
    """
    for candidate in (path, BASELINE_FILE_FALLBACK):
        if os.path.isfile(candidate):
            with open(candidate) as fh:
                data = json.load(fh)
            if data.get("schema_version") != SCHEMA_VERSION:
                raise ValueError(
                    f"Baseline schema version mismatch in {candidate}. "
                    "Re-create baseline with: sudo python3 lsim.py --baseline"
                )
            return data
    raise FileNotFoundError(
        f"No baseline found at {path} or {BASELINE_FILE_FALLBACK}. "
        "Run: sudo python3 lsim.py --baseline"
    )


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_to_baseline(baseline: dict) -> list:
    """
    Compare the current state of all files in the baseline against their
    stored hashes and metadata. Returns a list of Finding objects.

    CRITICAL — hash changed, or file is missing (was in baseline)
    HIGH     — permissions or owner changed
    """
    findings = []
    stored_files: dict = baseline.get("files", {})

    for filepath, stored in stored_files.items():
        exists = os.path.exists(filepath)

        if not exists:
            findings.append(Finding(
                category="File Integrity",
                severity=SEVERITY_CRITICAL,
                title=f"File deleted: {filepath}",
                detail=f"File was present at baseline creation but is now missing: {filepath}",
                recommendation=f"Investigate deletion of {filepath}. This may indicate tampering.",
                filepath=filepath,
                auto_remediate=False,
            ))
            continue

        current = _file_metadata(filepath)

        # Hash check
        if stored.get("hash") is not None and current["hash"] is not None:
            if current["hash"] != stored["hash"]:
                findings.append(Finding(
                    category="File Integrity",
                    severity=SEVERITY_CRITICAL,
                    title=f"File modified: {filepath}",
                    detail=(
                        f"Hash mismatch for {filepath}.\n"
                        f"  Baseline: {stored['hash']}\n"
                        f"  Current:  {current['hash']}"
                    ),
                    recommendation=f"Audit {filepath} for unauthorized changes.",
                    filepath=filepath,
                    auto_remediate=False,
                ))
        elif stored.get("hash") is None and current["hash"] is not None:
            # Previously unreadable, now readable — flag as changed
            findings.append(Finding(
                category="File Integrity",
                severity=SEVERITY_HIGH,
                title=f"File now readable: {filepath}",
                detail=f"{filepath} was unreadable at baseline but is now readable.",
                recommendation=f"Verify permissions change on {filepath} is intentional.",
                filepath=filepath,
                auto_remediate=False,
            ))

        # Permissions check
        if (stored.get("permissions") is not None
                and current["permissions"] is not None
                and current["permissions"] != stored["permissions"]):
            findings.append(Finding(
                category="File Integrity",
                severity=SEVERITY_HIGH,
                title=f"Permissions changed: {filepath}",
                detail=(
                    f"Permissions on {filepath} changed.\n"
                    f"  Baseline: {stored['permissions']}\n"
                    f"  Current:  {current['permissions']}"
                ),
                recommendation=f"Verify that permission change on {filepath} is intentional.",
                filepath=filepath,
                auto_remediate=False,
            ))

        # Owner check
        if (stored.get("uid") is not None
                and current["uid"] is not None
                and (current["uid"] != stored["uid"] or current["gid"] != stored["gid"])):
            findings.append(Finding(
                category="File Integrity",
                severity=SEVERITY_HIGH,
                title=f"Owner changed: {filepath}",
                detail=(
                    f"Owner/group of {filepath} changed.\n"
                    f"  Baseline: uid={stored['uid']} gid={stored['gid']}\n"
                    f"  Current:  uid={current['uid']} gid={current['gid']}"
                ),
                recommendation=f"Verify that ownership change on {filepath} is intentional.",
                filepath=filepath,
                auto_remediate=False,
            ))

    return findings
