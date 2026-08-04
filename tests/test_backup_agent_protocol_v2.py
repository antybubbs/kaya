import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.services.backup_agent_protocol import b64u_decode, canonical_query, canonical_request, seal_dispatch

sys.path.insert(0, str(Path(__file__).parents[1] / "external/Kaya-Docker-Agent"))
from protocol_v2 import ProtocolV2Client, b64u  # noqa: E402


VECTORS = json.loads((Path(__file__).parents[1] / "docs/security/backup-agent-protocol-v2-test-vectors.json").read_text(encoding="utf-8"))


def test_shared_signed_request_vector():
    vector = VECTORS["signed_request"]
    body = b64u_decode(vector["body_base64"])
    canonical = canonical_request(vector["method_on_wire"], vector["raw_path"], vector["raw_query"], vector["agent_id"], vector["key_id"], vector["request_id"], vector["timestamp"], body)
    assert canonical.decode() == vector["canonical_request"]
    Ed25519PublicKey.from_public_bytes(b64u_decode(VECTORS["keys"]["agent_ed25519_public"])).verify(b64u_decode(vector["ed25519_signature"]), canonical)
    assert canonical_query("tag=%c3%a9") == "tag=%C3%A9"


def test_shared_envelope_vector_is_reproduced_exactly():
    vector = VECTORS["envelope"]
    identity = SimpleNamespace(envelope_public_key=VECTORS["keys"]["agent_x25519_public"])
    server_key = SimpleNamespace(key_id="ssk_test_01")
    envelope = seal_dispatch(
        identity=identity,
        server_key=server_key,
        aad=vector["aad"],
        plaintext=vector["plaintext"],
        ephemeral_private=X25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["keys"]["ephemeral_x25519_private_hex"])),
        salt=b64u_decode(vector["hkdf_salt"]),
        nonce=b64u_decode(vector["nonce"]),
        server_private=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["keys"]["server_ed25519_private_seed_hex"])),
    )
    assert {key: envelope[key] for key in vector["outer_without_signature"]} == vector["outer_without_signature"]
    assert envelope["server_signature"] == vector["server_ed25519_signature"]


def test_server_envelope_is_opened_by_production_agent_implementation():
    agent_private = X25519PrivateKey.generate()
    server_private = Ed25519PrivateKey.generate()
    identity = SimpleNamespace(envelope_public_key=b64u(agent_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
    server_key = SimpleNamespace(key_id="synthetic-server-key")
    expires = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(timespec="seconds").replace("+00:00", "Z")
    manifest = {"job_id": "42", "operation": "backup", "policy": "full", "target_type": "local", "workload_ref": "synthetic-container"}
    import hashlib
    from app.services.backup_agent_protocol import canonical_json
    aad = {"agent_encryption_key_id": "synthetic-agent", "agent_id": "synthetic-agent", "claim_id": "5cc125d3-1a8f-4530-8584-c256c49f772b", "dispatch_id": "synthetic-dispatch", "expires_at": expires, "host_id": "7", "job_id": "42", "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(), "operation": "backup", "protocol_version": 2}
    plaintext = {"dispatch_grant": "synthetic-grant", "encryption": {"data_key": "synthetic-key", "mode": "agent-aes-256-gcm"}, "manifest": manifest, "target": {"type": "local", "path": "/synthetic"}}
    envelope = seal_dispatch(identity=identity, server_key=server_key, aad=aad, plaintext=plaintext, server_private=server_private)
    client = ProtocolV2Client.__new__(ProtocolV2Client)
    client.state = {
        "agent_id": "synthetic-agent",
        "envelope_private_key": b64u(agent_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
        "server_signing_keys": {"synthetic-server-key": b64u(server_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))},
    }
    assert client.open_envelope(envelope, "synthetic-dispatch", aad["claim_id"]) == plaintext
