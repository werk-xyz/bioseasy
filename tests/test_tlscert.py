# SPDX-License-Identifier: GPL-3.0-or-later
"""The self-signed certificate an installation without a reverse proxy serves itself.

What matters here is not that a file appears but that the certificate is one a browser could be
told to trust: the right kind of subject alternative name for each entry, a lifetime Apple's
platforms accept, a key nobody else can read, and renewal when the names change - that last one
being the failure that would otherwise go unnoticed, because the old certificate keeps working for
the old name while the new one silently matches nothing.
"""

from __future__ import annotations

import datetime as dt
import ipaddress

import pytest
from cryptography import x509

from bioseasy import tlscert


def names_in(cert_path):
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value


def test_a_name_becomes_dns_and_an_address_becomes_ip(tmp_path):
    """A browser opening https://192.168.1.10 looks at the IP entries and ignores the DNS ones, so
    an address written as a DNS name matches nothing at all."""
    cert_path, _key = tlscert.generate(tmp_path, ["backup.lan", "192.168.1.10", "fd00::1"])

    san = names_in(cert_path)
    assert san.get_values_for_type(x509.DNSName) == ["backup.lan"]
    assert san.get_values_for_type(x509.IPAddress) == [
        ipaddress.ip_address("192.168.1.10"),
        ipaddress.ip_address("fd00::1"),
    ]


def test_the_lifetime_stays_under_apples_limit(tmp_path):
    """Apple's platforms refuse a TLS certificate valid for more than 825 days, self-signed ones
    included - so a longer one would be rejected by exactly the devices this product is for."""
    cert_path, _key = tlscert.generate(tmp_path, ["backup.lan"])

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days

    assert days < 825


def test_the_private_key_is_not_readable_by_anyone_else(tmp_path):
    _cert, key_path = tlscert.generate(tmp_path, ["backup.lan"])

    assert key_path.stat().st_mode & 0o777 == 0o600


def test_a_certificate_is_renewed_when_the_names_change(tmp_path):
    """The quiet failure: somebody gives the machine a second address, restarts, and the old
    certificate keeps being served for a name it does not carry."""
    cert_path, _key = tlscert.generate(tmp_path, ["backup.lan"])

    assert tlscert.needs_renewal(cert_path, ["backup.lan"]) is False
    assert tlscert.needs_renewal(cert_path, ["backup.lan", "192.168.1.10"]) is True


def test_a_certificate_is_renewed_before_it_expires(tmp_path):
    cert_path, _key = tlscert.generate(tmp_path, ["backup.lan"])
    almost_over = dt.datetime.now(dt.UTC) + dt.timedelta(days=tlscert.VALID_DAYS - 1)

    assert tlscert.needs_renewal(cert_path, ["backup.lan"], now=almost_over) is True


def test_an_unreadable_certificate_is_replaced_rather_than_fatal(tmp_path):
    """A truncated or hand-edited file must not stop the server from coming up."""
    (tmp_path / tlscert.CERT_NAME).write_text("not a certificate")

    assert tlscert.needs_renewal(tmp_path / tlscert.CERT_NAME, ["backup.lan"]) is True


def test_ensure_keeps_the_certificate_it_already_made(tmp_path):
    """Restarting must not hand every browser a new certificate to be warned about again."""
    first_cert, first_key = tlscert.ensure(tmp_path, ["backup.lan"])
    first_bytes = first_cert.read_bytes()

    second_cert, second_key = tlscert.ensure(tmp_path, ["backup.lan"])

    assert (second_cert, second_key) == (first_cert, first_key)
    assert second_cert.read_bytes() == first_bytes


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("backup.lan, 192.168.1.10", ["backup.lan", "192.168.1.10"]),
        ("backup.lan;192.168.1.10", ["backup.lan", "192.168.1.10"]),
        (" a , , a , b ", ["a", "b"]),
        ("", []),
    ],
)
def test_names_are_read_forgivingly(raw, expected):
    assert tlscert.parse_names(raw) == expected


def test_a_certificate_without_a_name_is_refused(tmp_path):
    """Better a clear error at startup than a certificate that matches nothing."""
    with pytest.raises(ValueError, match="at least one name"):
        tlscert.generate(tmp_path, [])
