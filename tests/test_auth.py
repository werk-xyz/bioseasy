# SPDX-License-Identifier: GPL-3.0-or-later
from bioseasy.auth import LoginThrottle


def test_throttle_allows_free_attempts_then_backs_off():
    t = LoginThrottle(free=2, base_seconds=10, max_seconds=60)
    for now in (0, 1):
        assert t.wait_seconds("admin", now) == 0
        t.failed("admin", now)
    assert t.wait_seconds("admin", 2) == 9  # 10 s after the last failure at t=1
    t.failed("admin", 11)
    assert t.wait_seconds("admin", 12) == 19  # doubled to 20 s
    assert t.wait_seconds("someone-else", 12) == 0
    t.succeeded("admin")
    assert t.wait_seconds("admin", 12) == 0


# --- the email address, required for every account -----------------------------------------

import re  # noqa: E402 - the throttle test above needs no imports; these do
from contextlib import closing  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from bioseasy import auth, db, oidc  # noqa: E402

PASSWORD = "correct horse battery staple"  # noqa: S105 - throwaway test constant


@pytest.fixture
def conn(tmp_path):
    with closing(db.connect(tmp_path / "bioseasy.db")) as connection:
        db.migrate(connection)
        yield connection


@pytest.mark.parametrize("bad", ["", "   ", None, "not-an-address", "two@parts@example.test", "no@dot"])
def test_an_address_that_is_not_one_is_refused(bad):
    with pytest.raises(ValueError):
        auth.validate_email(bad)


def test_register_user_insists_on_an_address_where_create_user_still_tolerates_none(conn):
    """The split that keeps the address requirement without rewriting every programmatic caller:
    register_user is what the setup wizard and the admin page use, create_user is what the demo
    seed and older tests use and cannot supply an address for."""
    with pytest.raises(ValueError, match="email address is required"):
        auth.register_user(conn, "alice", PASSWORD, "member", "")
    assert auth.create_user(conn, "alice", PASSWORD, "member").email is None
    assert auth.register_user(conn, "bob", PASSWORD, "member", " bob@example.test ").email == "bob@example.test"


def test_only_the_known_callers_still_create_an_account_without_an_address(conn):
    """The guard behind that split: a new route reaching for create_user instead of register_user
    would quietly re-open the hole this closes, and nothing else would notice.

    Kept as a list of files rather than of call sites, so moving a call inside a module does not
    fail it. demo_seed.py is on the list because the demo deployment's demo user predates the
    requirement and has no address to give.
    """
    src = Path(__file__).resolve().parent.parent / "src" / "bioseasy"
    callers = sorted(
        path.name
        for path in src.rglob("*.py")
        if re.search(r"(?<!def )create_user\(", path.read_text(encoding="utf-8"))
    )
    assert callers == ["auth.py", "demo_seed.py"]


def test_one_address_belongs_to_one_account(conn):
    auth.register_user(conn, "alice", PASSWORD, "member", "shared@example.test")
    with pytest.raises(ValueError, match="taken"):
        auth.register_user(conn, "bob", PASSWORD, "member", "SHARED@example.test")


def test_an_admin_can_fill_in_a_missing_address_but_not_a_taken_one(conn):
    alice = auth.create_user(conn, "alice", PASSWORD, "member")
    bob = auth.register_user(conn, "bob", PASSWORD, "member", "bob@example.test")
    assert [row["username"] for row in auth.users_without_email(conn)] == ["alice"]

    auth.set_email(conn, alice.id, "alice@example.test")
    assert auth.users_without_email(conn) == []
    assert auth.get_user(conn, alice.id).email == "alice@example.test"

    with pytest.raises(ValueError, match="already uses that email address"):
        auth.set_email(conn, alice.id, "BOB@example.test")
    assert auth.get_user(conn, bob.id).email == "bob@example.test"


def test_a_self_registered_account_is_a_member_without_a_password(conn):
    user = auth.create_sso_user(conn, "newcomer", "newcomer@example.test")
    assert (user.role, user.email) == ("member", "newcomer@example.test")
    assert not auth.has_password(conn, user.id)
    assert auth.authenticate(conn, "newcomer", PASSWORD) is None
    with pytest.raises(ValueError, match="always a member"):
        auth.create_sso_user(conn, "elsewhere", "elsewhere@example.test", role="admin")


def test_an_address_two_accounts_share_signs_nobody_in(conn):
    """Only reachable in a database migrated from before users_email_unique (db.MIGRATIONS[20]),
    which is why the index is dropped here rather than the duplicate being inserted past it.
    Picking one of the two accounts would be a coin toss over who gets signed in."""
    auth.register_user(conn, "alice", PASSWORD, "member", "shared@example.test")
    conn.execute("DROP INDEX users_email_unique")
    auth.register_user(conn, "bob", PASSWORD, "member", "shared@example.test")

    with pytest.raises(oidc.Refused, match="More than one account"):
        oidc.find_user_by_email(conn, "shared@example.test")


def test_an_address_is_matched_whatever_case_the_provider_reports_it_in(conn):
    alice = auth.register_user(conn, "alice", PASSWORD, "member", "Alice@Example.Test")
    assert oidc.find_user_by_email(conn, "alice@example.test") == alice.id
    assert oidc.find_user_by_email(conn, "somebody@example.test") is None


def test_a_username_for_a_new_identity_avoids_the_ones_already_taken(conn):
    auth.register_user(conn, "newcomer", PASSWORD, "member", "taken@example.test")
    assert oidc.username_for(conn, {"preferred_username": "newcomer"}, "x@example.test") == "newcomer-2"
    assert oidc.username_for(conn, {}, "someone@example.test") == "someone"
