# SPDX-License-Identifier: GPL-3.0-or-later
"""The realistic-backup writer moved to `bioseasy.demo_backup` when `demo_seed.py` started using
it as well. This shim keeps the short `from fixtures import ...` that eight test modules use."""

from bioseasy.demo_backup import (
    BACKUP_PASSWORD,
    DEFAULT_FILES,
    BackupFile,
    RealisticBackup,
    write_realistic_backup,
)

__all__ = ["BACKUP_PASSWORD", "DEFAULT_FILES", "BackupFile", "RealisticBackup", "write_realistic_backup"]
