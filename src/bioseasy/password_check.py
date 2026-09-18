# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove the operator still knows the backup encryption password, without ever storing it.

Unwraps the `BackupKeyBag` from `Manifest.plist` the same way a real restore would, using
pyiosbackup (already a dependency of pymobiledevice3):

- `pyiosbackup.manifest_plist.ManifestPlist.from_path` reads and parses only `Manifest.plist`.
- `pyiosbackup.keybag.Keybag.from_manifest` (pyiosbackup/keybag.py:50) derives the unwrapping
  key from the password via PBKDF2 and then unwraps each class key with
  `cryptography.hazmat.primitives.keywrap.aes_key_unwrap`. That call enforces the AES key-wrap
  standard's integrity check and raises `InvalidUnwrap` when the derived key is wrong, i.e. when
  the password is wrong. Nothing outside `Manifest.plist` is read and no backup file content is
  decrypted; this was verified by constructing a real encrypted `Manifest.plist` fixture and
  exercising both branches (see tests/test_password_check.py).

The key derivation is deliberately slow (PBKDF2, tens of thousands of iterations) so brute
forcing is expensive. That same cost means a single request could otherwise tie up the server:
`check()` runs it in a worker thread with a hard timeout and never waits for a thread that
overruns it.
"""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
from pyiosbackup.keybag import Keybag
from pyiosbackup.manifest_plist import ManifestPlist

log = logging.getLogger("bioseasy")

Outcome = Literal["correct", "wrong", "not_encrypted", "unreadable"]

TIMEOUT_SECONDS = 60

_MESSAGES: dict[Outcome, str] = {
    "correct": "The password is correct.",
    "wrong": "That password does not unlock this backup.",
    "not_encrypted": "This backup is not encrypted; there is no password to check.",
    "unreadable": "The backup manifest could not be read.",
}


@dataclass(frozen=True)
class CheckResult:
    outcome: Outcome
    message: str  # safe to show to the user; never derived from or containing the password


def _unwrap(manifest_path: Path, password: str) -> Outcome:
    """Runs in a worker thread. Must never log, return or raise the password itself."""
    try:
        manifest = ManifestPlist.from_path(manifest_path)
    except (FileNotFoundError, OSError, ValueError, KeyError, TypeError):
        # ValueError/KeyError/TypeError cover a truncated or foreign plist that plistlib parses
        # but that lacks the shape ManifestPlist expects.
        log.warning("could not read backup manifest at %s", manifest_path)
        return "unreadable"

    try:
        encrypted = manifest.is_encrypted
    except KeyError:
        log.warning("backup manifest at %s has no IsEncrypted field", manifest_path)
        return "unreadable"
    if not encrypted:
        del password
        return "not_encrypted"

    try:
        Keybag.from_manifest(manifest, password)
    except InvalidUnwrap:
        return "wrong"
    except Exception as exc:
        # Anything other than a clean wrong-password rejection: a malformed or foreign keybag
        # blob (missing SALT/ITER/CLAS/WPKY, an IndexError from a missing class marker, a
        # construct parse error, ...). Logged as the exception class only, never its message:
        # construct's parse errors can echo back parsed field values, which must never end up
        # anywhere near a log line.
        log.warning("could not evaluate keybag in %s (%s)", manifest_path, exc.__class__.__name__)
        return "unreadable"
    finally:
        del password
    return "correct"


def check(backup_dir: Path, password: str) -> CheckResult:
    """Check whether `password` unlocks the encrypted backup keybag in `backup_dir`.

    Only `backup_dir / "Manifest.plist"` is read; no other backup file is opened and no backup
    content is decrypted. The password is passed to a worker thread and never logged, stored,
    returned or echoed anywhere, including in error messages.
    """
    manifest_path = backup_dir / "Manifest.plist"
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="password-check")
    future = pool.submit(_unwrap, manifest_path, password)
    del password
    try:
        outcome = future.result(timeout=TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        # Only the manifest path and the timeout are logged, per the docstring guarantee above:
        # `password` was deleted from this frame's scope two lines up and is never in reach here.
        log.warning(  # nosemgrep: python-logger-credential-disclosure
            "password check on %s exceeded %ss, abandoning it", manifest_path, TIMEOUT_SECONDS
        )
        outcome = "unreadable"
    except Exception as exc:
        # Class name only, like _unwrap: a parse error's message or traceback can echo manifest
        # fields such as the device serial, and personal data does not belong in logs either.
        log.warning(  # nosemgrep: python-logger-credential-disclosure
            "password check on %s failed unexpectedly (%s)", manifest_path, exc.__class__.__name__
        )
        outcome = "unreadable"
    finally:
        # Never block the request on a worker that overran the timeout (e.g. a hostile
        # Manifest.plist with an absurd PBKDF2 iteration count): let it finish on its own.
        pool.shutdown(wait=False)
    return CheckResult(outcome, _MESSAGES[outcome])
