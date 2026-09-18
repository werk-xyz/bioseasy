# SPDX-License-Identifier: GPL-3.0-or-later
"""docs.py: the closed allowlist, raw-HTML escaping, relative-link rewriting, and the /guide
routes. See docs.py's module docstring for why the allowlist is a dict lookup rather than a
filesystem path built from the request.
"""

import re
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from bioseasy import auth, db, docs
from bioseasy.app import create_app
from bioseasy.config import Settings
from bioseasy.engine.demo import DemoEngine

PASSWORD = "correct horse battery"


# --- Unit tests against docs.render(), no app needed ---


def test_render_returns_none_for_a_slug_outside_the_allowlist(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n")
    assert docs.render(tmp_path, "concept") is not None  # sanity: a real allowlisted page works
    assert docs.render(tmp_path, "not-a-real-page") is None


@pytest.mark.parametrize(
    "slug",
    [
        "../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "concept.md",  # the allowlist key is "concept", not the filename
        "concept/../../../etc/passwd",
        "",
        "decisions",  # a real docs/ file, deliberately not in the allowlist (see module docstring)
        "spike",
        "research",
        "publication-checklist",
        "design",  # removed from PAGES: contributor CSS/token reference
        "roadmap",  # removed from PAGES: contributor status tracker
    ],
)
def test_render_rejects_every_non_allowlisted_slug(tmp_path, slug):
    (tmp_path / "concept.md").write_text("# Concept\n")
    assert docs.render(tmp_path, slug) is None


def test_render_is_still_safe_if_the_allowlist_ever_pointed_outside_docs_dir(tmp_path, monkeypatch):
    """Break the guard on purpose (CONTRIBUTING.md: a check that never ran red proves nothing).

    PAGES is a fixed module constant in real use; this simulates what would happen if a future
    edit ever mapped a slug to a path escaping docs_dir, to prove _within actually catches it
    rather than only the "slug not a dict key" branch ever being exercised.
    """
    outside = tmp_path / "outside.md"  # one level above docs_dir, matching "../outside.md" below
    outside.write_text("# Outside\n")
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    monkeypatch.setitem(docs.PAGES, "concept", ("../outside.md", "Concept"))
    try:
        assert docs.render(docs_dir, "concept") is None  # red without _within; confirmed by hand
    finally:
        monkeypatch.setitem(docs.PAGES, "concept", ("concept.md", "Concept"))


def test_raw_html_in_a_doc_is_escaped_not_executed(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n\n<script>alert(1)</script>\n\nSome text.\n")
    page = docs.render(tmp_path, "concept")
    assert "<script>" not in page.html
    assert "&lt;script&gt;" in page.html


def test_markdown_blockquote_syntax_still_works_after_tag_escaping(tmp_path):
    """Regression: an earlier version escaped every '<' and '>' in the source, which also
    neutralised Markdown's own leading '>' blockquote marker (docs/install.md uses one for its
    "Status" note and its sqlite.org quote)."""
    (tmp_path / "concept.md").write_text("# Concept\n\n> A quoted line.\n> Second line.\n")
    page = docs.render(tmp_path, "concept")
    assert "<blockquote>" in page.html
    assert "&gt; A quoted line." not in page.html


def test_table_is_wrapped_in_its_own_scroll_container(tmp_path):
    """docs/design.md: only tables, diagrams and code blocks may exceed the page width, each
    inside its own scrolling container - the page body must never scroll sideways. Wide tables
    (env vars, routes, platforms) are exactly what docs/*.md leans on."""
    (tmp_path / "concept.md").write_text("# Concept\n\n| A | B |\n|---|---|\n| 1 | 2 |\n")
    page = docs.render(tmp_path, "concept")
    assert '<div class="table-scroll"><table>' in page.html
    assert page.html.count('<div class="table-scroll">') == page.html.count("<table>")
    assert page.html.rstrip().endswith("</table></div>") or "</table></div>" in page.html


def test_two_tables_on_one_page_are_wrapped_separately(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n\n| A |\n|---|\n| 1 |\n\nText between.\n\n| B |\n|---|\n| 2 |\n")
    page = docs.render(tmp_path, "concept")
    assert page.html.count('<div class="table-scroll">') == 2
    assert page.html.count("</div>") >= 2
    assert "Text between." in page.html
    # The wrap must not swallow the paragraph between the two tables into one span.
    assert page.html.index("Text between.") > page.html.index("</table></div>")


def test_a_doc_with_no_table_gets_no_scroll_wrapper(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n\nJust prose, no table.\n")
    page = docs.render(tmp_path, "concept")
    assert "table-scroll" not in page.html


def test_table_wrapping_does_not_disturb_html_escaping(tmp_path):
    """The table wrap runs after _escape_tags/_rewrite_links; a <script> elsewhere on the same
    page must stay inert regardless."""
    (tmp_path / "concept.md").write_text("# Concept\n\n<script>alert(1)</script>\n\n| A |\n|---|\n| 1 |\n")
    page = docs.render(tmp_path, "concept")
    assert "<script>" not in page.html
    assert "&lt;script&gt;" in page.html
    assert '<div class="table-scroll"><table>' in page.html


def test_relative_link_to_an_allowlisted_page_is_rewritten_to_the_docs_route(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n\nSee [install](install.md#3-storage) too.\n")
    (tmp_path / "install.md").write_text("# Installation\n")
    page = docs.render(tmp_path, "concept")
    assert 'href="/guide/install#3-storage"' in page.html


def test_relative_link_to_a_non_allowlisted_page_is_not_a_dead_link_to_the_route(tmp_path):
    (tmp_path / "concept.md").write_text("# Concept\n\nSee [extra](extra.md) too.\n")
    (tmp_path / "extra.md").write_text("# Extra\n")
    page = docs.render(tmp_path, "concept")
    # Never point at a /guide/extra route that would just 404.
    assert "/guide/extra" not in page.html


def test_nav_lists_every_allowlisted_page_and_nothing_else():
    slugs = {slug for slug, _title in docs.nav()}
    assert slugs == set(docs.PAGES)
    assert "decisions" not in slugs
    assert "spike" not in slugs
    assert "research" not in slugs
    assert "design" not in slugs  # removed from PAGES, contributor-only
    assert "roadmap" not in slugs  # removed from PAGES, contributor-only


def test_every_published_page_sits_in_exactly_one_docs_section():
    """The grouped index (docs.SECTIONS) must cover PAGES exactly.

    Without this, adding a page to PAGES gives it a working URL and no link anywhere - the failure
    mode the flat list could not have, and the price of grouping. Also checks the reverse: a
    section naming a slug that no longer exists would render a dead link.
    """
    in_sections = [slug for _label, _intro, slugs in docs.SECTIONS for slug in slugs]

    assert sorted(in_sections) == sorted(docs.PAGES), (
        f"sections cover {sorted(in_sections)}, PAGES has {sorted(docs.PAGES)}"
    )
    assert len(in_sections) == len(set(in_sections)), "a page appears in more than one section"

    # Every page also carries a sentence: a grouped index whose entries are bare titles is the
    # flat list again, only taller.
    missing = [slug for slug in docs.PAGES if not docs.DESCRIPTIONS.get(slug)]
    assert not missing, f"no description for {missing}"


def test_docs_index_shows_sections_and_descriptions(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")

    page = client.get("/guide").text
    for label, _intro, _slugs in docs.SECTIONS:
        assert label in page, label
    assert docs.DESCRIPTIONS["restore"] in page


def test_default_docs_dir_resolves_to_the_real_docs_folder_in_this_checkout():
    real_docs = docs.default_docs_dir()
    assert (real_docs / "concept.md").is_file()
    assert (real_docs / "install.md").is_file()


def test_real_configuration_page_wraps_its_actual_tables_in_a_scroll_container():
    """Not a synthetic fixture: docs/configuration.md is the page built out of wide tables - every
    environment variable with its default and a sentence of explanation. It took over that role
    from install.md, whose duplicated variable tables were replaced by a
    pointer to this one page."""
    real_docs = docs.default_docs_dir()
    page = docs.render(real_docs, "configuration")
    assert "<table>" in page.html  # sanity: the fixture assumption (install.md has tables) holds
    assert page.html.count('<div class="table-scroll">') == page.html.count("<table>")


def test_every_published_page_renders_without_error_against_the_real_docs_dir():
    """No sampling: every slug in PAGES, not just install/concept."""
    real_docs = docs.default_docs_dir()
    for slug in docs.PAGES:
        page = docs.render(real_docs, slug)
        assert page is not None, f"{slug} failed to render"
        assert page.html  # non-empty


# --- Route-level tests ---


@pytest.fixture
def env(tmp_path):
    data, root, docs_dir = tmp_path / "data", tmp_path / "backups", tmp_path / "docs"
    data.mkdir()
    root.mkdir()
    docs_dir.mkdir()
    (docs_dir / "concept.md").write_text("# Concept\n\nHello docs.\n")
    settings = Settings(data, root, "demo", "test-secret", False, 3600, docs_dir=docs_dir)
    with TestClient(
        create_app(settings, DemoEngine(step_seconds=0), huey_immediate=True), follow_redirects=False
    ) as client:
        yield client, settings


def csrf(client, url):
    return re.search(r'name="csrf" value="([^"]+)"', client.get(url).text).group(1)


def conn_for(settings):
    return closing(db.connect(settings.data_dir / "bioseasy.db"))


def login(client, username):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf": token, "username": username, "password": PASSWORD})
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_docs_index_requires_sign_in(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    r = client.get("/guide")
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_docs_index_lists_pages_for_a_member_not_only_an_admin(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "member")
    page = client.get("/guide")
    assert page.status_code == 200
    assert 'href="/guide/concept"' in page.text


def test_docs_page_renders_allowlisted_slug(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get("/guide/concept")
    assert page.status_code == 200
    assert "Hello docs." in page.text


@pytest.mark.parametrize("slug", ["decisions", "not-a-page", "concept.md", "spike", "research", "design", "roadmap"])
def test_docs_page_404s_for_anything_not_in_the_allowlist(env, slug):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
    login(client, "admin")
    page = client.get(f"/guide/{slug}")
    assert page.status_code == 404


def test_footer_links_to_docs_for_both_admin_and_member(env):
    client, settings = env
    with conn_for(settings) as conn:
        auth.create_user(conn, "admin", PASSWORD, "admin")
        auth.create_user(conn, "member", PASSWORD, "member")
    login(client, "admin")
    footer = re.search(r"<footer\b.*?</footer>", client.get("/").text, re.DOTALL).group(0)
    assert re.search(r'href="/guide"[^>]*>Docs<', footer)
    client.post("/logout", data={"csrf": csrf(client, "/")})
    login(client, "member")
    footer = re.search(r"<footer\b.*?</footer>", client.get("/").text, re.DOTALL).group(0)
    assert re.search(r'href="/guide"[^>]*>Docs<', footer)
    assert "/admin/about" not in footer
