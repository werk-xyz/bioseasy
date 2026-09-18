# SPDX-License-Identifier: GPL-3.0-or-later
"""NOTICE must not silently fall behind uv.lock.

`scripts/check_notice_coverage.py` is the actual guard; this test just makes it part of the
normal `pytest` run instead of a separate step someone has to remember. See that script's
docstring for what "covered" means and what a tool-failure looks like versus a real gap.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_notice_coverage import (  # noqa: E402
    find_missing,
    load_notice_text,
    normalize,
    runtime_dependency_names,
)


def test_every_runtime_dependency_is_named_in_notice():
    dependency_names = runtime_dependency_names()
    notice_text = load_notice_text()

    missing = find_missing(dependency_names, notice_text)

    assert not missing, f"NOTICE does not name {len(missing)} runtime dependency(ies) from uv.lock: {sorted(missing)}"


def test_normalize_folds_name_variants():
    # The guard against a name that only differs by case or separator slipping past unnoticed.
    assert normalize("Foo-Bar") == normalize("foo_bar") == normalize("foo.bar") == "foo-bar"


def test_find_missing_flags_an_absent_dependency():
    # Break the guard on purpose (a dependency NOTICE has never heard of) and see it go red.
    missing = find_missing(["totally-invented-package"], "NOTICE mentions nothing relevant here.")
    assert missing == ["totally-invented-package"]


def test_find_missing_accepts_a_present_dependency():
    missing = find_missing(["aiofiles"], "See the aiofiles row in the table below.")
    assert missing == []
