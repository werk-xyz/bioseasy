# Building and releasing

For contributors and maintainers. Operators do not need this page - [Installation](install.md)
runs a published image.

Two artifacts come out of this repository, and they are released **separately** because they have
separate lives: the **server**, as a container image, and the **pairing helper app**, as a desktop
binary per platform. A shared version number would force a helper release for every server fix
and tell a user nothing.

| Artifact | Built by | Tag that publishes it | Where it lands |
|---|---|---|---|
| Container image | `.github/workflows/container.yml` | `v1.2.3` | GitHub Container Registry, plus a GitHub release |
| Helper app (macOS, Windows, Linux) | `.github/workflows/helper.yml` | `helper-v1.2.3` | A GitHub release with one binary per platform |

Neither pipeline deploys anywhere. What runs where is a decision a human makes with a compose
file.

## Run the checks the pipeline runs

```sh
uv sync
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q
```

That is exactly what `.github/workflows/ci.yml` does, so a green checkout means a green pipeline.
The snapshot tests take real hard-linked snapshots and need `rsync` on the machine.

## Build the container image

```sh
docker build -t bioseasy:local .
```

Or through compose, which is the same build with the tag wired up:

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

The image is multi-architecture in CI (`linux/amd64` and `linux/arm64`) because a good share of
home servers and NAS boxes are arm64. A local `docker build` produces only your own architecture;
use `docker buildx build --platform linux/amd64,linux/arm64` if you need both.

Pass the commit you are building so the web UI footer can name it:

```sh
docker build --build-arg GITHUB_SHA="$(git rev-parse --short HEAD)" -t bioseasy:local .
```

Without it the footer omits the revision rather than showing a blank one.

## Build the helper app

PyInstaller cannot cross-build: each platform is built on that platform. CI does all three on
their own runners; by hand, from `helper/`:

```sh
# macOS (Apple Silicon)
uv run --python 3.12 --group build pyinstaller \
  --name bioseasy-pair --windowed --clean --noconfirm \
  --collect-all pymobiledevice3 --collect-data certifi \
  --osx-bundle-identifier org.bioseasy.pairhelper --target-architecture arm64 \
  bioseasy_pair_helper.py

# Linux (x64) and Windows (x64): the same call without the three macOS-only flags, plus --onefile
```

The build can be checked without any device: `bioseasy-pair --self-test` imports pymobiledevice3,
lists USB devices without touching them, resolves the CA bundle and calls `/healthz` on a server
you name. See `helper/README.md` for the rest.

**None of these builds is signed, and that is intended.** macOS Gatekeeper blocks the app on
first launch and Windows SmartScreen warns; the release page says how to get past both.

## Cut a release

1. Move `CHANGELOG.md`'s `[Unreleased]` section under the new version heading with today's date,
   and open a fresh `[Unreleased]`.
2. Commit that, then tag:

   ```sh
   git tag -a v1.2.3 -m "1.2.3"        # server and container image
   git tag -a helper-v1.2.3 -m "..."   # helper app, only when it changed
   git push --follow-tags
   ```

3. The container workflow builds and pushes `1.2.3`, `1.2` and `latest`, then opens a GitHub
   release whose notes are that version's changelog section. It **fails** if the changelog has no
   section for the tag, which is deliberate: a release nobody described is worse than a late one.
4. The image is scanned by digest for HIGH/CRITICAL vulnerabilities - a finding fails the run -
   and its CycloneDX SBOM is attached to the release.
5. The helper workflow builds all three platforms and attaches them to their own release, with
   LICENSE and NOTICE.

### Once, after the first release

- **Make the image public.** A new package on the GitHub Container Registry starts private, and
  its visibility is set separately from the repository's. Until it is public, `docker compose pull`
  fails with `unauthorized` for everyone who is not signed in. Package settings, "Change
  visibility".
- **Turn on private vulnerability reporting** in the repository's security settings.
  `SECURITY.md` sends reporters there.

## The demo deployment

```sh
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d
```

Simulated devices, seeded content, one published port, no host networking, nothing that touches a
real iPhone. Everything lives in named volumes, so `docker compose down -v` removes every trace.
It signs visitors in automatically as a demo account whose credentials are in the source - never
point it at real data.
