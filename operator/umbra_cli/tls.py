"""Certificate pinning for the operator console.

A pin is the SHA-256 of the SubjectPublicKeyInfo of a certificate.  Two
certificates that carry the same key have the same pin, so a certificate
that is renewed keeps its pin, while a certificate that only claims the
same name does not have it.

The pin is what a console uses when it does not want to trust a chain of
certificates: the server that holds the pinned key is the server, whoever
wrote the certificate and whoever signed it.  The check happens right
after the TLS handshake and before the umbra handshake, so a console that
refuses the pin never sends its token to the wrong peer.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

__all__ = [
    "spki_pin",
    "spki_pin_of_pem",
    "pin_matches",
    "peer_certificate",
    "hostname_matches",
    "env_pin",
]


def spki_pin(cert: x509.Certificate) -> str:
    """The pin of a certificate: the hex SHA-256 of its public key.

    The public key is taken in its DER form, the way it is written in the
    certificate, so the answer is the same on every implementation.
    """
    der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def spki_pin_of_pem(path: str) -> str:
    """The pin of the first certificate in a PEM file.

    It is what the operator writes into the configuration of the server
    and into the command line of the console.  A file that holds several
    certificates is read like the server reads it: the first one counts.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    certs = []
    try:
        certs = list(x509.load_pem_x509_certificates(raw))
    except AttributeError:  # pragma: no cover - old cryptography
        certs = [x509.load_pem_x509_certificate(raw)]
    except ValueError:
        certs = []
    if not certs:
        raise ValueError(f"{path} holds no certificate")
    return spki_pin(certs[0])


def pin_matches(cert: Optional[x509.Certificate], want: str) -> bool:
    """Whether the certificate carries one of the pinned keys.

    The pin may be a list, separated by commas: the old key and the new
    one are both welcome while a handover lasts.

    The comparison is constant time: the pin is public, but the moment a
    peer is refused says something about it.  Every pin of the list is
    compared, so the time the check takes does not say which one of them
    matched.
    """
    if cert is None or not want:
        return False
    digest = spki_pin(cert)
    matched = False
    for part in want.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if hmac.compare_digest(digest, part):
            matched = True
    return matched


def peer_certificate(sock: object) -> Optional[x509.Certificate]:
    """The certificate of the peer, or nothing when there is none.

    The socket has to be an SSL socket: a plain one has no peer
    certificate, and a console that is not on TLS has nothing to pin.
    """
    getter = getattr(sock, "getpeercert", None)
    if getter is None:
        return None
    try:
        der = getter(binary_form=True)
    except (OSError, ValueError):
        return None
    if not der:
        return None
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError:
        return None


def hostname_matches(cert: Optional[x509.Certificate], name: str) -> bool:
    """Whether the certificate carries the name.

    The name is checked by hand because a console that pins a key does
    not need a chain of certificates to trust: the pin is the trust, and
    the name is the second question the server has to answer.
    """
    if cert is None or not name:
        return False
    import ipaddress

    try:
        wanted = ipaddress.ip_address(name)
    except ValueError:
        wanted = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        for entry in san:
            if wanted is not None and isinstance(entry, x509.IPAddress):
                if entry.value == wanted:
                    return True
            if wanted is None and isinstance(entry, x509.DNSName):
                if entry.value.lower() == name.lower():
                    return True
            if wanted is None and isinstance(entry, x509.UniformResourceIdentifier):
                if entry.value.lower().startswith("https://" + name.lower()):
                    return True
        return False
    # A certificate without a name extension is not usable for a name
    # check: the common name alone is not a name any more.
    return False


def env_pin(name: str = "UMBRA_TLS_PIN") -> str:
    """The pin in the environment, or an empty string."""
    return (os.environ.get(name) or "").strip()
