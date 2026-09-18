# syntax=docker/dockerfile:1
# SPDX-License-Identifier: GPL-3.0-or-later

# Build stage: compilers only live here; some pymobiledevice3 dependencies may build from source.
FROM docker.io/library/python:3.12-slim AS build
# Unpinned on purpose: these packages track whatever the base image's Debian release ships that
# day, the same way the base image tag itself is not pinned to a digest. A version pin here would go stale
# on the next Debian point release and buys no security margin the base image tag does not
# already buy; it would only turn a routine `apt-get update` into a broken build.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.11.26
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM docker.io/library/python:3.12-slim
LABEL org.opencontainers.image.title="bioseasy" \
      org.opencontainers.image.description="Self-hosted Wi-Fi backups for iPhone and iPad" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
# rsync takes the snapshots. usbmuxd is the USB multiplexer pymobiledevice3 talks to when a device
# is paired at the server; docs/pairing.md, "USB at the server", uses the host's daemon instead.
# Same reasoning as the build stage above: unpinned, tracking the base image's own Debian point
# release rather than a version string that would go stale on the next rebuild.
# `apt-get upgrade` pulls Debian security fixes the upstream python image has not been rebuilt
# with yet - it can lag by days, long enough for CRITICAL findings in a fresh python:3.12-slim.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends usbmuxd rsync \
 && rm -rf /var/lib/apt/lists/*
# Both mount points exist in the image and belong to group 0 with group write, so named volumes
# start writable and an arbitrary `user:` from compose (PUID with group 0) works too.
RUN useradd --system --uid 10001 --gid 0 --home-dir /data --no-create-home bioseasy \
 && mkdir -p /data /backups \
 && chown 10001:0 /data /backups \
 && chmod 0770 /data /backups
COPY --from=build /app/.venv /app/.venv
COPY LICENSE /usr/share/doc/bioseasy/LICENSE
COPY NOTICE /usr/share/doc/bioseasy/NOTICE
# Rendered by the web UI at /guide, /guide/<page> (docs.py, PAGES allowlist); not every file here
# is actually shown, see docs.py's module docstring for which ones and why.
COPY docs /app/docs
# HOME=/data puts pymobiledevice3's pair records into the app volume, never onto the backup share.
ENV PATH=/app/.venv/bin:$PATH \
    HOME=/data \
    BIOSEASY_DATA_DIR=/data \
    BIOSEASY_BACKUP_ROOT=/backups \
    BIOSEASY_DOCS_DIR=/app/docs \
    BIOSEASY_PORT=8080 \
    PYTHONUNBUFFERED=1
# The commit this image was built from, shown in the footer. CI passes it as a build argument; a
# local build without one leaves it empty and the footer omits it. Declared last so a new commit
# does not invalidate the cached layers above.
ARG GITHUB_SHA=""
ENV BIOSEASY_REVISION=${GITHUB_SHA}
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["python", "-m", "bioseasy.healthcheck"]
CMD ["bioseasy"]
