# Security policy

bioseasy handles device pair records and full device backups. Please report vulnerabilities
privately, not in public issues.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository: the Security tab, "Report a
vulnerability". It reaches the maintainers without the report ever being public, and it needs no
mailbox that somebody has to remember to watch.

Include what you found, how to reproduce it, and which version you tested.

## What is in scope

- Authentication, sessions, CSRF, access to device routes
- Exposure of pair records, backup contents or settings
- The container image and its default configuration

## Design notes

- The backup encryption password is never stored.
- Pair records stay in the app data volume with restrictive permissions.
- The long-running container needs no privileges; USB access is only used by the one-time
  pairing run.

## Software bill of materials (SBOM)

`.github/workflows/security.yml` produces a CycloneDX SBOM of the repository's dependencies,
`uv.lock` included, on every run and keeps it as a workflow artifact (`bioseasy-dependency-sbom`,
14 days). It describes what the source tree declares, not what a particular image contains.
