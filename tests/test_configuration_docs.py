# SPDX-License-Identifier: GPL-3.0-or-later
"""The configuration reference cannot fall behind the code.

`docs/configuration.md` is the one page an operator reads before starting the container, and the
one most likely to go stale: a new `BIOSEASY_*` variable is added where it is read, and nobody
remembers the table. So the table is checked rather than promised.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "bioseasy"
REFERENCE = Path(__file__).resolve().parents[1] / "docs" / "configuration.md"

# Prefix constants, not variables: diagnostics.py reports *whether any* BIOSEASY_OIDC_* variable
# is set, so these two strings are a prefix test and have nothing to document on their own.
NOT_A_VARIABLE = {"BIOSEASY_OIDC", "BIOSEASY_OIDC_"}

# Read by docker-compose.yml, not by bioseasy. The reference documents them because an operator
# sets them in the same .env file, but no Python code will ever mention them.
COMPOSE_LEVEL = {"BIOSEASY_IMAGE"}

NAME = re.compile(r"BIOSEASY_[A-Z0-9_]+")


def _variables_read_by_the_code() -> set[str]:
    found: set[str] = set()
    for path in SRC.rglob("*.py"):
        found.update(NAME.findall(path.read_text()))
    return found - NOT_A_VARIABLE


def test_every_environment_variable_the_code_reads_is_documented():
    documented = set(NAME.findall(REFERENCE.read_text()))
    missing = sorted(_variables_read_by_the_code() - documented)
    assert not missing, f"not in docs/configuration.md: {', '.join(missing)}"


def test_the_reference_documents_nothing_that_no_longer_exists():
    read = _variables_read_by_the_code()
    stale = sorted(set(NAME.findall(REFERENCE.read_text())) - read - COMPOSE_LEVEL)
    assert not stale, f"documented but read nowhere in src/: {', '.join(stale)}"


@pytest.mark.parametrize("variable", ["BIOSEASY_DATA_DIR", "BIOSEASY_OIDC_ISSUER", "BIOSEASY_TLS_NAMES"])
def test_the_guard_looks_at_the_file_it_claims_to(variable):
    """A spot check that the page really is the source being read, not an empty match."""
    assert variable in REFERENCE.read_text()
