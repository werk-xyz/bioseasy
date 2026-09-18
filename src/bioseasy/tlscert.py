# SPDX-License-Identifier: GPL-3.0-or-later
"""A self-signed certificate for installations with no reverse proxy in front.

Why this exists: bioseasy speaks plain HTTP and expects a proxy to terminate TLS, which is right
for anyone who already runs one and leaves everybody else on an unencrypted LAN page. This module
lets the container serve HTTPS on its own, with a certificate it makes itself.

What a self-signed certificate does and does not buy, so nobody is surprised (docs/install.md says
the same at more length): the connection is encrypted, session cookies with the `Secure` flag work,
and backups are unaffected either way because a backup is a separate TLS session with the device.
Browsers will warn until the certificate is trusted on the machine that opens the page, and
browser notifications and the home-screen web app need that trust because a service worker only
runs in what the browser considers an authenticated context.

Both of those are the reason this writes real subject alternative names for every name and address
the installation is reached at: a certificate without a matching SAN cannot be trusted by a
browser at all, however often it is clicked past, so it could never be installed as a trusted one
either.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)

CERT_NAME = "server.crt"
KEY_NAME = "server.key"
# 820 days. Apple's platforms reject a TLS certificate valid for more than 825 days, and a
# self-signed one is no exception (Apple, "Requirements for trusted certificates in iOS 13 and
# macOS 10.15"), so a ten-year certificate would be refused by exactly the devices this product is
# for. Renewed automatically below, so the length costs nobody anything.
VALID_DAYS = 820
RENEW_BEFORE_DAYS = 30


def _san(name: str) -> x509.GeneralName:
    """An IP address entry for something that parses as an address, a DNS entry otherwise.

    The distinction matters: a browser opening `https://192.168.1.10` checks the IP entries and
    ignores the DNS ones, so an address written as a DNS name matches nothing.
    """
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def parse_names(raw: str) -> list[str]:
    """The configured names, in order, without blanks or duplicates."""
    seen, names = set(), []
    for part in raw.replace(";", ",").split(","):
        name = part.strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def needs_renewal(cert_path: Path, names: list[str], now: dt.datetime | None = None) -> bool:
    """Whether the certificate on disk is missing, expiring, or no longer covers these names.

    The last case is the one that would otherwise go unnoticed: somebody gives the machine a name
    or a second address, restarts, and the old certificate keeps being served for a name it does
    not carry.
    """
    if not cert_path.is_file():
        return True
    now = now or dt.datetime.now(dt.UTC)
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        present = {str(entry.value) for entry in san}
    except Exception:  # noqa: BLE001 - an unreadable certificate is simply replaced
        return True
    if cert.not_valid_after_utc - dt.timedelta(days=RENEW_BEFORE_DAYS) <= now:
        return True
    return not set(names) <= present


def generate(directory: Path, names: list[str]) -> tuple[Path, Path]:
    """Write a fresh certificate and key, and return their paths.

    An EC key rather than RSA: every browser and every Apple platform in scope accepts P-256, it is
    faster to make, and nothing here needs to interoperate with anything older.
    """
    if not names:
        raise ValueError("a certificate needs at least one name or address")
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / CERT_NAME, directory / KEY_NAME

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # A minute of leeway, so a client whose clock runs slightly behind the server does not
        # reject a certificate that was just written.
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName([_san(name) for name in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # The private key is the one file here that must not be world-readable; /data holds pair
    # records at 0600 for the same reason.
    key_path.chmod(0o600)
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def ensure(directory: Path, names: list[str]) -> tuple[Path, Path]:
    """The pair of files to hand uvicorn, generated on first start and renewed when due."""
    cert_path, key_path = directory / CERT_NAME, directory / KEY_NAME
    if needs_renewal(cert_path, names) or not key_path.is_file():
        cert_path, key_path = generate(directory, names)
        log.warning(
            "Serving HTTPS with a self-signed certificate for %s. Browsers will warn until it is "
            "trusted on the machine opening the page; see docs/install.md.",
            ", ".join(names),
        )
    return cert_path, key_path
