# SPDX-License-Identifier: GPL-3.0-or-later
import datetime
from contextlib import closing

import pytest

from bioseasy import db, handoff

NOW = datetime.datetime(2026, 9, 15, 12, 0, 0, tzinfo=datetime.UTC)


@pytest.fixture
def conn(tmp_path):
    with closing(db.connect(tmp_path / "bioseasy.db")) as c:
        db.migrate(c)
        c.execute("INSERT INTO users (id, username, password_hash, role) VALUES (1, 'admin', 'x', 'admin')")
        c.execute("INSERT INTO users (id, username, password_hash, role) VALUES (2, 'other', 'x', 'admin')")
        yield c


def test_code_is_never_stored_in_plain(conn):
    code, expires_at = handoff.create_code(conn, 1, NOW)
    assert len(code) == handoff.CODE_LENGTH
    assert all(ch in handoff.CODE_ALPHABET for ch in code)
    row = conn.execute("SELECT * FROM pairing_codes").fetchone()
    assert code not in row["code_hash"]
    assert row["code_hash"] == handoff._hash(code)
    assert expires_at == row["expires_at"]


def test_alphabet_excludes_ambiguous_characters():
    assert not set(handoff.CODE_ALPHABET) & set("0O1IL")


def test_fourth_open_code_is_refused(conn):
    for _ in range(handoff.MAX_OPEN_CODES_PER_USER):
        handoff.create_code(conn, 1, NOW)
    with pytest.raises(handoff.TooManyOpenCodesError):
        handoff.create_code(conn, 1, NOW)
    # A different user is unaffected by another user's open codes.
    handoff.create_code(conn, 2, NOW)


def test_expired_open_codes_do_not_count_against_the_limit(conn):
    for _ in range(handoff.MAX_OPEN_CODES_PER_USER):
        handoff.create_code(conn, 1, NOW)
    later = NOW + datetime.timedelta(minutes=handoff.CODE_TTL_MINUTES + 1)
    handoff.create_code(conn, 1, later)  # every earlier code has expired by "later"


def test_consume_accepts_an_open_code_exactly_once(conn):
    code, _ = handoff.create_code(conn, 1, NOW)
    row = handoff.consume(conn, code, NOW)
    assert row is not None
    handoff.mark_consumed(conn, row["id"], "UDID", NOW)
    assert handoff.consume(conn, code, NOW) is None  # single use


def test_consume_rejects_expired_code(conn):
    code, _ = handoff.create_code(conn, 1, NOW)
    later = NOW + datetime.timedelta(minutes=handoff.CODE_TTL_MINUTES + 1)
    assert handoff.consume(conn, code, later) is None


def test_consume_rejects_unknown_code(conn):
    assert handoff.consume(conn, "ZZZZZZZZ", NOW) is None


def test_get_code_is_scoped_to_the_creating_user(conn):
    code, _ = handoff.create_code(conn, 1, NOW)
    assert handoff.get_code(conn, 1, code) is not None
    assert handoff.get_code(conn, 2, code) is None  # a different admin cannot see it
    assert handoff.get_code(conn, 1, "ZZZZZZZZ") is None


def test_build_script_embeds_code_base_url_and_pinned_version():
    script = handoff.build_script("https://bioseasy.example", "ABCD2345", "11.12.5")
    assert "CODE = 'ABCD2345'" in script
    assert "BASE_URL = 'https://bioseasy.example'" in script
    assert "pymobiledevice3==11.12.5" in script
