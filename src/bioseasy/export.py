# SPDX-License-Identifier: GPL-3.0-or-later
"""A whole backup generation as one streamed tar, byte for byte as it lies on disk.

This is a different thing from `extract.tar_stream`, and the difference is the whole point. That
one hands out files a person wants to read: decrypted, named `<domain>/<relative path>`. Useful to
look at, worthless to restore from - Finder, Apple Devices and iMazing need the backup's own
layout, encrypted exactly as the device wrote it: `Info.plist`, `Manifest.plist`, `Status.plist`,
`Manifest.db` and the payloads under their two-hex-character hash directories.

So this module copies the directory and changes nothing: no decryption, no renaming, no filtering.
The backup password is not needed and never touches this path - whoever restores the archive gives
it to Finder, not to us.

Deliberately no `Range` support and no resume: a tar built on the
fly is not seekable, so serving a byte offset would mean regenerating the archive and throwing the
first N bytes away. On a large backup that is worse than starting again, and a resume that costs
more than the transfer it saves is a resume only on paper.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

CHUNK_BYTES = 1024 * 1024


class _Sink:
    """Collects what tarfile writes, so the generator below can hand it on in pieces."""

    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def write(self, data: bytes) -> int:
        self.parts.append(data)
        return len(data)

    def drain(self) -> bytes:
        data = b"".join(self.parts)
        self.parts.clear()
        return data


def archive_name(device_name: str | None, udid: str, generation: str, kind: str = "backup") -> str:
    """A file name that says which device, which generation, and which of the two archives it is.

    The `kind` suffix is not decoration. Two different downloads come out of one generation - the
    picked files, decrypted and readably named, and the whole backup exactly as it lies - and
    without it both would be called `<device>-<generation>.tar`. Whoever downloaded both ended up
    with that name and a copy of it, unable to tell which was which, and the difference is the one
    that matters: only the second can be restored from.

    Stripped of anything that could end the `filename=` parameter early or start a new header
    line - the device name is chosen by whoever named the device, not by us.
    """
    base = f"{device_name or udid}-{generation}"
    cleaned = "".join(character for character in base if character.isalnum() or character in "-_. ")
    return f"{(cleaned.strip().replace(' ', '_') or udid)}-{kind}.tar"


def tar_stream(snapshot_dir: Path, *, chunk_bytes: int = CHUNK_BYTES):
    """The whole directory as a tar, streamed, nothing staged on disk or held whole in memory.

    Entries are named relative to the directory, so unpacking gives exactly the backup folder back
    and it can be dropped into `MobileSync/Backup/<UDID>`. Files are walked in sorted order so two
    downloads of the same generation produce the same archive; a snapshot never changes after it
    was taken, so that holds over time as well.
    """
    sink = _Sink()
    # "w|" is the streaming mode: it never seeks, which is what allows a multi-gigabyte backup to
    # go out through a socket without a temporary file.
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(p for p in snapshot_dir.rglob("*") if p.is_file() and not p.is_symlink()):
            info = tar.gettarinfo(str(path), arcname=str(path.relative_to(snapshot_dir)))
            # The uid/gid of the container user say nothing to whoever unpacks this, and a numeric
            # id that happens to exist on their machine is worse than none.
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as handle:
                tar.addfile(info, handle)
            if data := sink.drain():
                yield from _in_chunks(data, chunk_bytes)
    if data := sink.drain():
        yield from _in_chunks(data, chunk_bytes)


def _in_chunks(data: bytes, chunk_bytes: int):
    for start in range(0, len(data), chunk_bytes):
        yield data[start : start + chunk_bytes]
