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
    _negotiate_tls,
    _parse_certificate,
    discover_rdp_certificate,
)


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


def _serve_one_rdp_tls_connection(listener: socket.socket, ssl_context: ssl.SSLContext) -> None:
    connection, _ = listener.accept()
    with connection:
        request = connection.recv(len(_NEGOTIATION_REQUEST))
        assert request == _NEGOTIATION_REQUEST
        # TPKT + X.224 CC + RDP_NEG_RSP(type=0x02) selecting PROTOCOL_SSL.
        response = bytes(
            [
                0x03, 0x00, 0x00, 0x13,
                0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
            ]
        )
        connection.sendall(response)
        tls_connection = ssl_context.wrap_socket(connection, server_side=True)
        try:
            tls_connection.recv(1)
        except (ssl.SSLError, OSError):
            pass


def _start_test_server(cert_path, key_path):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(str(cert_path), str(key_path))
    thread = threading.Thread(target=_serve_one_rdp_tls_connection, args=(listener, ssl_context), daemon=True)
    thread.start()
    return port, listener, thread


def test_discover_rdp_certificate_end_to_end(tmp_path):
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

    port, listener, thread = _start_test_server(cert_path, key_path)
    try:
        candidate = discover_rdp_certificate("127.0.0.1", port, timeout=5.0)
    finally:
        listener.close()
        thread.join(timeout=2)

    expected_fingerprint = _parse_certificate(certificate.public_bytes(serialization.Encoding.DER)).fingerprint
    assert candidate.fingerprint == expected_fingerprint
    assert candidate.self_signed is True


def test_discover_rdp_certificate_reports_clear_error_on_connection_refused():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()  # closed immediately: nothing is listening on this port

    with pytest.raises(ValueError):
        discover_rdp_certificate("127.0.0.1", port, timeout=2.0)


def test_negotiate_tls_rejects_server_that_refuses_tls():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_failure():
        connection, _ = listener.accept()
        with connection:
            connection.recv(len(_NEGOTIATION_REQUEST))
            failure = bytes(
                [
                    0x03, 0x00, 0x00, 0x13,
                    0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
                ]
            )
            connection.sendall(failure)

    thread = threading.Thread(target=serve_failure, daemon=True)
    thread.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
            with pytest.raises(ValueError, match="refused to negotiate"):
                _negotiate_tls(sock)
    finally:
        listener.close()
        thread.join(timeout=2)
