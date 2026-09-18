# Contributing

Thanks for helping. A few things keep this project easy to work on.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Device bugs need: iOS version, device model, bioseasy version, pymobiledevice3 version, and
  whether the device was locked or charging.
- Include the output of `docker compose exec worker bioseasy diagnose`. It is built to be safe
  to paste into a public issue: no notification URLs, secret key, setup token, pair record
  content, full device identifiers or device names leave it.

## Development setup

```sh
uv sync
uv run pytest
uv run ruff check src tests
uv run ruff format src tests
```

The demo engine (`BIOSEASY_ENGINE=demo`) simulates devices, so most work needs no iPhone.

## Guidelines

- English for code, comments, UI text and docs.
- Comments explain why, not what.
- Keep dependencies few and well maintained; discuss new ones in the issue first.
- Every route that touches a device goes through the ownership guard in `app.py`.
- UI colours, fonts and the layout primitive come from `docs/design.md`.
- Tests for every behaviour change. A test that has never failed proves nothing: break the code
  once and watch it go red.

## Security checks

`.github/workflows/security.yml` runs on every push and pull request, and once a week on its own
because advisories appear without anyone touching the code. Each of the following is blocking: a
real finding fails the job.

- **Gitleaks** scans the full git history for committed secrets. The few exceptions are listed in
  `.gitleaks.toml`, each tied to the exact value rather than a file, each a marked fake or a false
  positive with the reason next to it.
- **Semgrep** scans the code for dangerous patterns, using the `p/python`, `p/fastapi` and
  `p/security-audit` registry rulesets.
- **OSV-Scanner** checks `uv.lock` against the OSV advisory database.
- **Hadolint** lints the `Dockerfile`. Any ignored rule is justified inline, next to the
  instruction it applies to.
- **Trivy** scans the repository filesystem (`trivy.yaml`: dependencies and misconfiguration,
  threshold HIGH/CRITICAL).

## Sign-off

Commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

By signing off you state that you have the right to submit the change under the project's
license, GPL-3.0-or-later.
