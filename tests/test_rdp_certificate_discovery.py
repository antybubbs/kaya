import socket
import ssl
import threading
from datetime import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.rdp_certificate_discovery import (
    _NEGOTIATION_REQUEST,
    _PROTOCOL_HYBRID,
    _negotiate_tls,
    _parse_certificate,
    discover_rdp_certificate,
)


def _negotiation_response(*, neg_type: int, protocol_or_failure: int) -> bytes:
    """Build a TPKT + X.224 CC + RDP_NEG_RSP/FAILURE reply.

    neg_type: 0x02 (RDP_NEG_RSP, success) or 0x03 (RDP_NEG_FAILURE).
    protocol_or_failure: selectedProtocol (success) or failureCode (failure).
    """
    payload = protocol_or_failure.to_bytes(4, "little")
    return bytes(
        [0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, neg_type, 0x00, 0x08, 0x00]
    ) + payload


def _self_signed_cert(*, common_name="rdp-test-host", sans=("rdp-test-host",)):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1))
        .not_valid_after(datetime(2034, 1, 1))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]), critical=False
        )
    certificate = builder.sign(key, hashes.SHA256())
    return key, certificate


# ---------------------------------------------------------------------------
# Unit tests: certificate parsing (no network involved).
# ---------------------------------------------------------------------------


def test_parse_certificate_extracts_expected_fields():
    _key, certificate = _self_signed_cert(sans=("rdp-test-host", "alt.rdp-test-host"))
    der = certificate.public_bytes(serialization.Encoding.DER)

    candidate = _parse_certificate(der)

    assert candidate.fingerprint.startswith("sha256:")
    assert len(candidate.fingerprint) == len("sha256:") + 64
    assert "rdp-test-host" in candidate.subject
    assert candidate.self_signed is True
    assert candidate.not_valid_before == datetime(2024, 1, 1)
    assert candidate.not_valid_after == datetime(2034, 1, 1)
    assert set(candidate.sans) == {"rdp-test-host", "alt.rdp-test-host"}


def test_parse_certificate_detects_non_self_signed_subject_issuer_mismatch():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf-host")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "some-ca")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1))
        .not_valid_after(datetime(2034, 1, 1))
        .sign(key, hashes.SHA256())
    )
    candidate = _parse_certificate(certificate.public_bytes(serialization.Encoding.DER))
    assert candidate.self_signed is False


def test_parse_certificate_handles_missing_sans():
    _key, certificate = _self_signed_cert(sans=())
    candidate = _parse_certificate(certificate.public_bytes(serialization.Encoding.DER))
    assert candidate.sans == []


def test_parse_certificate_rejects_garbage_der():
    with pytest.raises(ValueError):
        _parse_certificate(b"not-a-certificate")


# ---------------------------------------------------------------------------
# End-to-end: a local TCP server speaking the minimal RDP negotiation + TLS,
# exercising discover_rdp_certificate's full path once.
# ---------------------------------------------------------------------------


def _serve_one_rdp_tls_connection(
    listener: socket.socket, ssl_context: ssl.SSLContext, *, received: list | None = None
) -> None:
    connection, _ = listener.accept()
    with connection:
        request = connection.recv(len(_NEGOTIATION_REQUEST))
        assert request == _NEGOTIATION_REQUEST
        # Real negotiation logic, exactly like an NLA-enforcing Windows Server:
        # refuse outright unless the client offers CredSSP/HYBRID, matching the
        # exact failure this fix addresses (RDP_NEG_FAILURE before any TLS byte).
        requested_protocols = int.from_bytes(request[15:19], "little")
        if not requested_protocols & _PROTOCOL_HYBRID:
            connection.sendall(_negotiation_response(neg_type=0x03, protocol_or_failure=5))
            return
        connection.sendall(_negotiation_response(neg_type=0x02, protocol_or_failure=_PROTOCOL_HYBRID))
        tls_connection = ssl_context.wrap_socket(connection, server_side=True)
        # Prove no credentials are sent: after TLS, the client must send
        # nothing further (a real CredSSP TSRequest would arrive here).
        tls_connection.settimeout(1.0)
        try:
            leftover = tls_connection.recv(1)
        except (TimeoutError, ssl.SSLError, OSError):
            leftover = b""
        if received is not None:
            received.append(leftover)


def _start_test_server(cert_path, key_path, *, received: list | None = None):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(str(cert_path), str(key_path))
    thread = threading.Thread(
        target=_serve_one_rdp_tls_connection, args=(listener, ssl_context), kwargs={"received": received}, daemon=True
    )
    thread.start()
    return port, listener, thread


def _write_test_cert(tmp_path):
    key, certificate = _self_signed_cert()
    key_path = tmp_path / "key.pem"
    cert_path = tmp_path / "cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path, certificate


def test_discover_rdp_certificate_succeeds_against_nla_enforcing_server(tmp_path):
    """Regression test for the exact reported failure: a modern Windows
    Server with NLA enforced sends RDP_NEG_FAILURE unless the client offers
    CredSSP/HYBRID. _serve_one_rdp_tls_connection refuses any negotiation
    request that omits PROTOCOL_HYBRID, exactly like such a server.
    """
    key_path, cert_path, certificate = _write_test_cert(tmp_path)
    received: list = []

    port, listener, thread = _start_test_server(cert_path, key_path, received=received)
    try:
        candidate = discover_rdp_certificate("127.0.0.1", port, timeout=5.0)
    finally:
        listener.close()
        thread.join(timeout=2)

    expected_fingerprint = _parse_certificate(certificate.public_bytes(serialization.Encoding.DER)).fingerprint
    assert candidate.fingerprint == expected_fingerprint
    assert candidate.self_signed is True
    # No CredSSP TSRequest (or anything else) was sent after the TLS
    # handshake: discovery never transmits credentials.
    assert received == [b""]


def test_discover_rdp_certificate_reports_clear_error_on_connection_refused():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()  # closed immediately: nothing is listening on this port

    with pytest.raises(ValueError):
        discover_rdp_certificate("127.0.0.1", port, timeout=2.0)


def test_negotiation_request_offers_both_ssl_and_hybrid():
    # The exact byte this bug was about: requestedProtocols must include
    # PROTOCOL_HYBRID (bit 1), not just PROTOCOL_SSL (bit 0), or an
    # NLA-enforcing server refuses the negotiation before TLS ever starts.
    requested_protocols = int.from_bytes(_NEGOTIATION_REQUEST[15:19], "little")
    assert requested_protocols & _PROTOCOL_HYBRID


@pytest.mark.parametrize(
    ("failure_code", "expected_text"),
    [
        (5, "Network Level Authentication"),
        (2, "does not allow TLS-secured connections"),
        (99, "failure code 99"),
    ],
)
def test_negotiate_tls_reports_the_specific_failure_reason(failure_code, expected_text):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_failure():
        connection, _ = listener.accept()
        with connection:
            connection.recv(len(_NEGOTIATION_REQUEST))
            connection.sendall(_negotiation_response(neg_type=0x03, protocol_or_failure=failure_code))

    thread = threading.Thread(target=serve_failure, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            with pytest.raises(ValueError, match=expected_text):
                _negotiate_tls(sock)
    finally:
        listener.close()
        thread.join(timeout=2)
