"""Read-only RDP TLS certificate discovery.

Mirrors the trust posture of ``scan_ssh_host_key`` (app/routers/remote_manager.py):
Kaya retrieves the certificate the server presents but never validates or
trusts it here. RDP negotiates its transport before any TLS byte can be sent
(MS-RDPBCGR): the client sends a fixed X.224 Connection Request carrying an
RDP Negotiation Request that asks for TLS, the server replies with its
Negotiation Response, and only then does the TLS handshake begin. There is no
standalone tool for this step analogous to ``ssh-keyscan`` (``openssl
s_client`` has no RDP STARTTLS mode), so this module implements the minimal
fixed-byte negotiation itself rather than shelling out.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

# Fixed 19-byte TPKT + X.224 Connection Request carrying an RDP Negotiation
# Request that asks only for TLS (requestedProtocols = PROTOCOL_SSL = 1).
# This exact byte layout is standard across RDP scanners/clients; it is not
# server- or version-specific.
_NEGOTIATION_REQUEST = bytes(
    [
        0x03, 0x00, 0x00, 0x13,  # TPKT: version 3, reserved, length=19
        0x0E,                    # X.224 length indicator (14 bytes follow)
        0xE0,                    # X.224 Connection Request TPDU code
        0x00, 0x00,              # DST-REF
        0x00, 0x00,              # SRC-REF
        0x00,                    # class option
        0x01,                    # RDP_NEG_REQ type
        0x00,                    # flags
        0x08, 0x00,              # length = 8 (little-endian)
        0x01, 0x00, 0x00, 0x00,  # requestedProtocols = PROTOCOL_SSL (little-endian)
    ]
)
_MIN_NEGOTIATION_RESPONSE = 4 + 7 + 8  # TPKT + X.224 CC fixed part + RDP_NEG_RSP/FAILURE
_NEG_TYPE_RESPONSE = 0x02
_NEG_TYPE_FAILURE = 0x03


@dataclass(frozen=True)
class RdpCertificateCandidate:
    fingerprint: str  # canonical "sha256:<64 lowercase hex>", matches normalise_rdp_cert_fingerprints()
    subject: str
    issuer: str
    self_signed: bool  # heuristic (subject == issuer); not cryptographic proof
    not_valid_before: datetime
    not_valid_after: datetime
    sans: list[str]


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ValueError("The remote host closed the connection during RDP negotiation.")
        chunks.extend(chunk)
    return bytes(chunks)


def _negotiate_tls(sock: socket.socket) -> None:
    """Complete the RDP pre-TLS negotiation, raising if TLS is unavailable."""
    sock.sendall(_NEGOTIATION_REQUEST)
    header = _recv_exact(sock, 4)
    if header[0] != 0x03:
        raise ValueError("The remote host did not respond with a valid RDP negotiation reply.")
    total_length = (header[2] << 8) | header[3]
    if total_length < _MIN_NEGOTIATION_RESPONSE:
        raise ValueError(
            "The remote host does not support TLS-negotiated RDP connections; "
            "certificate discovery is not available for this server."
        )
    body = _recv_exact(sock, total_length - 4)
    # body: [0]len indicator [1]CC CDT [2:4]DST-REF [4:6]SRC-REF [6]class option [7]neg type [8]flags [9:11]len [11:15]payload
    neg_type = body[7]
    if neg_type == _NEG_TYPE_FAILURE:
        raise ValueError("The remote host refused to negotiate a TLS-secured RDP connection.")
    if neg_type != _NEG_TYPE_RESPONSE:
        raise ValueError("The remote host returned an unrecognised RDP negotiation response.")


def _parse_certificate(der: bytes) -> RdpCertificateCandidate:
    certificate = x509.load_der_x509_certificate(der)
    subject = certificate.subject.rfc4514_string()
    issuer = certificate.issuer.rfc4514_string()
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = [str(name.value) for name in extension.value]
    except x509.ExtensionNotFound:
        sans = []
    return RdpCertificateCandidate(
        fingerprint=f"sha256:{hashlib.sha256(der).hexdigest()}",
        subject=subject,
        issuer=issuer,
        self_signed=subject == issuer,
        not_valid_before=certificate.not_valid_before_utc.replace(tzinfo=None),
        not_valid_after=certificate.not_valid_after_utc.replace(tzinfo=None),
        sans=sans,
    )


def discover_rdp_certificate(
    host: str, port: int, *, timeout: float = 8.0
) -> RdpCertificateCandidate:
    """Retrieve the certificate an RDP server presents, without trusting it.

    Raises ValueError with an actionable, non-leaky message on any failure
    (connection, negotiation, TLS or parsing). Never used for the real
    session - the certificate returned here is for administrator review only.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            _negotiate_tls(raw_sock)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    except TimeoutError as exc:
        raise ValueError(
            "Kaya could not reach the RDP server in time. Confirm the address and port."
        ) from exc
    except (OSError, ssl.SSLError) as exc:
        raise ValueError(
            "Kaya could not retrieve the RDP certificate. Confirm the address, port, and that "
            "the service supports TLS-secured RDP."
        ) from exc
    if not der:
        raise ValueError("The RDP server did not present a certificate.")
    try:
        return _parse_certificate(der)
    except ValueError as exc:
        raise ValueError("Kaya could not parse the certificate presented by the RDP server.") from exc
