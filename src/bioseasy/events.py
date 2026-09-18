# SPDX-License-Identifier: GPL-3.0-or-later
"""Device events every signed-in user may see for their own devices: only an admin sees all logs;
these are dedicated events derived from records that clearly belong to one device and therefore
to one user, shown only in that user's own log.

Why this is a separate module and not a filter over `log_entries`
----------------------------------------------------------------
`log_entries` holds free-text log records from both processes. Its `udid` column is filled by
`logview._extract_udid`, a regex over the formatted message, and that function's own docstring
says what it is for: filtering the admin page, "never for anything security-relevant". A record
with no recognisable UDID, or one naming two devices, cannot be attributed at all. Scoping a
free-text log by a best-effort regex would be a guess presented as a boundary, so this module
never reads that table. A member's feed is built only from rows that carry a real foreign key to
`devices`, and the scope is applied in SQL through a JOIN, not by filtering afterwards - the same
pattern status.py's `for_owner`/`for_admin` use throughout.

Why these two sources
---------------------
Both keep history and both reference a device:

- `runs` - one row per backup attempt, kept indefinitely, with the outcome and the message the
  device page already shows for that same run.
- `snapshot_verifications` - one row per (device, generation) deep verification, with `checked_at`.

Three tables that look like candidates and are deliberately not used:

- `activities` is a live registry for the header's indicator, not a journal: `activity.sweep_stale`
  deletes finished rows after `FINISHED_RETENTION` (10 minutes) and stale ones after 60 seconds.
  A log built on it would be empty ten minutes later.
- `netcheck_runs` holds exactly one row per device, overwritten on every check. It answers "what
  did the last connectivity check say", never "when did connections fail" - there is no history in
  it to report, and inventing a sequence of events from a single overwritten row would assert
  something the data does not hold.
- `log_entries`, for the reason above.

What `detail` may contain
-------------------------
`runs.message` is the same text the device page renders for a run, and `jobs._finish` passes
`str(exc)` into it on a failure, so it can carry an engine message or a path. That is pre-existing
exposure, not new: `/devices/{udid}` is guarded by `visible_device`, and `device_summary` reads
these very rows, so a member could already read this text for their own devices. This module never
widens it - the owner scope here is the same one that guards that page.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

PAGE_SIZE = 50

# What a row of this feed can be about. Kept as an explicit tuple, like activity.KINDS, so a
# future source registers here rather than inventing its own string at a call site.
KINDS = ("backup", "verification")

KIND_LABELS: dict[str, str] = {
    "backup": "Backup",
    "verification": "Generation check",
}

# Outcome vocabularies of the two sources, mapped to one display shape. The words differ per
# source on purpose - a backup "succeeded", a generation is "verified" - and are kept rather than
# flattened into a single "ok", which would lose what was actually checked.
#
# The pill class is the same token set _macros.html's status_pill uses, so state never rests on
# colour alone (docs/design.md): every entry carries a word as well.
OUTCOME_DISPLAY: dict[str, tuple[str, str]] = {
    # runs.status, minus 'running' - an unfinished backup is not an event yet
    "succeeded": ("ok", "Succeeded"),
    "failed": ("bad", "Failed"),
    "not_confirmed": ("warn", "Not confirmed"),
    "cancelled": ("muted", "Cancelled"),
    # snapshot_verifications.outcome
    "verified": ("ok", "Verified"),
    "missing": ("bad", "Files missing"),
    "not_checked": ("warn", "Not checked"),
}

TRIGGER_LABELS: dict[str, str] = {
    "manual": "started by hand",
    "schedule": "on schedule",
    "device": "started from the device",
    "api": "started through the API",
}

# One SELECT per source, unioned. Both join `devices` rather than reading the udid column alone:
# the join is what carries `owner_id`, and for a member it is an INNER join, so a row whose device
# has since been deleted - or which belongs to nobody - cannot appear in their feed. `finished_at`
# is NULL on a row a worker never got to finish, so the timestamp falls back to `started_at`
# instead of sorting as NULL.
_UNION = """
SELECT COALESCE(r.finished_at, r.started_at) AS at,
       'backup' AS kind,
       r.status AS outcome,
       r.message AS detail,
       r.trigger AS trigger,
       NULL AS snapshot_name,
       d.udid AS udid,
       d.name AS device_name,
       d.owner_id AS owner_id,
       u.username AS owner_name
FROM runs r
JOIN devices d ON d.udid = r.udid
LEFT JOIN users u ON u.id = d.owner_id
WHERE r.status <> 'running'{owner}
UNION ALL
SELECT v.checked_at AS at,
       'verification' AS kind,
       v.outcome AS outcome,
       v.detail AS detail,
       NULL AS trigger,
       v.snapshot_name AS snapshot_name,
       d.udid AS udid,
       d.name AS device_name,
       d.owner_id AS owner_id,
       u.username AS owner_name
FROM snapshot_verifications v
JOIN devices d ON d.udid = v.udid
LEFT JOIN users u ON u.id = d.owner_id
WHERE 1 = 1{owner}
"""

_OWNER_CLAUSE = " AND d.owner_id = ?"


@dataclass(frozen=True)
class EventPage:
    rows: list[sqlite3.Row]
    total: int
    page: int
    page_size: int

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total


def _query(owner_id: int | None, kind: str | None, udid: str | None) -> tuple[str, list]:
    """The unioned SELECT plus its parameters, in the order the two halves consume them.

    `owner_id` None means an admin view (no owner clause at all); any other value confines both
    halves of the union. The clause is a fixed constant, never interpolated user input - the
    values travel as bound parameters, twice, once per half.
    """
    owner = _OWNER_CLAUSE if owner_id is not None else ""
    sql = _UNION.format(owner=owner)
    params: list = []
    if owner_id is not None:
        params.append(owner_id)
    # The second half of the union repeats the same parameters in the same order.
    half = list(params)
    params = params + half
    inner = f"SELECT * FROM ({sql}) e"  # noqa: S608 - `sql` is built from module constants only
    where, extra = [], []
    if kind:
        where.append("e.kind = ?")
        extra.append(kind)
    if udid:
        where.append("e.udid = ?")
        extra.append(udid)
    if where:
        inner += " WHERE " + " AND ".join(where)
    return inner, [*params, *extra]


def list_events(
    conn: sqlite3.Connection,
    *,
    owner_id: int | None = None,
    kind: str | None = None,
    udid: str | None = None,
    page: int = 1,
    page_size: int = PAGE_SIZE,
) -> EventPage:
    """Newest first, optionally narrowed to one kind or one device.

    `owner_id` is the whole access decision: pass a user id for a member's own feed, or None for
    the admin view across every device. A caller that wants a member's feed must pass their id -
    there is no "current user" here to forget, and no post-filtering step that could be skipped.

    `udid` narrows within whatever scope `owner_id` already set; on a member's feed it can only
    ever match one of their own devices, because the owner clause is part of the same query.
    """
    kind = kind if kind in KINDS else None
    inner, params = _query(owner_id, kind, udid)
    total = conn.execute(f"SELECT COUNT(*) FROM ({inner})", params).fetchone()[0]  # noqa: S608
    page = max(1, page)
    rows = conn.execute(
        f"SELECT * FROM ({inner}) ORDER BY at DESC, udid LIMIT ? OFFSET ?",  # noqa: S608
        [*params, page_size, (page - 1) * page_size],
    ).fetchall()
    return EventPage(rows=rows, total=total, page=page, page_size=page_size)


def shape(rows: list[sqlite3.Row]) -> list[dict]:
    """Rows turned into the small, UI-ready shape the template renders: a label for what happened,
    the device it happened to, a pill class plus a word for the outcome, and the detail text.

    An outcome this module does not know is shown as itself with a neutral pill rather than being
    dropped or relabelled - a new status value in `runs` or `snapshot_verifications` should look
    unfamiliar on the page, not silently become "Succeeded".
    """
    shaped = []
    for row in rows:
        cls, word = OUTCOME_DISPLAY.get(row["outcome"], ("muted", row["outcome"]))
        shaped.append(
            {
                "at": row["at"],
                "kind": row["kind"],
                "label": KIND_LABELS.get(row["kind"], row["kind"]),
                "outcome": row["outcome"],
                "outcome_class": cls,
                "outcome_word": word,
                "detail": row["detail"] or "",
                "trigger": TRIGGER_LABELS.get(row["trigger"], "") if row["trigger"] else "",
                "snapshot_name": row["snapshot_name"],
                "udid": row["udid"],
                "device_name": row["device_name"] or row["udid"],
                # Only the admin-wide view renders this; a member's own feed has exactly one
                # possible value for it. "No owner" is shown as itself rather than left blank -
                # an unowned device is a state to fix, not an absent name.
                "owner_name": row["owner_name"] or "No owner",
            }
        )
    return shaped


def devices_in_scope(conn: sqlite3.Connection, owner_id: int | None) -> list[sqlite3.Row]:
    """The devices whose events this scope can contain, for the page's device filter.

    Built from the same owner clause as the feed itself, so the dropdown can never offer a device
    the feed would refuse to show - the mismatch that would otherwise let a member learn that some
    other device exists by finding it in a filter list.
    """
    if owner_id is None:
        return conn.execute("SELECT udid, name FROM devices ORDER BY name, udid").fetchall()
    return conn.execute("SELECT udid, name FROM devices WHERE owner_id = ? ORDER BY name, udid", (owner_id,)).fetchall()
