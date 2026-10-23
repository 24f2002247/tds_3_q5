import base64
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.canonical import canonical_bytes, proposal_digest
from app.database import SessionLocal
from app.main import app
from app.models import Evaluation, ReceiptRecord
from app.receipt_verifier import verify_receipt
from .test_api import request_body


def test_ed25519_receipt_signature():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verifier = {
        "algorithm": "Ed25519",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
        },
    }
    receipt = {
        "dossierId": "d",
        "callId": "call-1234567890ab",
        "action": "no_action",
        "accepted": True,
        "proposalDigest": "a" * 64,
        "receiptId": "r-001",
    }
    message = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": "e",
        "inputDigest": "b" * 64,
        "receipt": receipt,
    }
    signed = {
        **receipt,
        "receiptSignature": base64.b64encode(private.sign(canonical_bytes(message))).decode(),
    }
    assert verify_receipt(verifier, "e", "b" * 64, signed)


def _committable_evaluation(dossier_count: int = 1):
    evaluation_id = "receipt-" + uuid.uuid4().hex
    body = request_body(evaluation_id)
    if dossier_count == 2:
        second = dict(body["dossiers"][0])
        second["dossierId"] = second["dossierId"] + "-2"
        body["dossiers"] = [body["dossiers"][0], second]

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    body["receiptVerifier"]["publicKeyJwk"]["x"] = (
        base64.urlsafe_b64encode(public).rstrip(b"=").decode()
    )
    with TestClient(app) as client:
        proposed = client.post("/v1/mailroom/actions", json=body)
    assert proposed.status_code == 200
    return body, private, proposed.json()


def _signed_receipt(private, evaluation_id, input_digest, proposal, accepted=True):
    receipt = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "accepted": accepted,
        "proposalDigest": proposal_digest(proposal),
        "receiptId": "receipt-" + uuid.uuid4().hex,
    }
    message = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": evaluation_id,
        "inputDigest": input_digest,
        "receipt": receipt,
    }
    return {
        **receipt,
        "receiptSignature": base64.b64encode(private.sign(canonical_bytes(message))).decode(),
    }


def _commit_request(body, input_digest, receipts):
    return {
        "profile": body["profile"],
        "operation": "commit",
        "evaluationId": body["evaluationId"],
        "inputDigest": input_digest,
        "receipts": receipts,
    }


def test_invalid_signature_is_rejected_without_commit():
    body, private, proposed = _committable_evaluation()
    receipt = _signed_receipt(private, body["evaluationId"], proposed["inputDigest"], proposed["proposals"][0])
    receipt["receiptSignature"] = base64.b64encode(b"invalid_signature_bytes_12345678").decode()
    commit = _commit_request(body, proposed["inputDigest"], [receipt])
    with TestClient(app) as client:
        response = client.post("/v1/mailroom/actions", json=commit)
    assert response.status_code == 422


def test_mismatched_proposal_digest_is_rejected():
    body, private, proposed = _committable_evaluation()
    receipt = _signed_receipt(private, body["evaluationId"], proposed["inputDigest"], proposed["proposals"][0])
    receipt["proposalDigest"] = "0" * 64
    commit = _commit_request(body, proposed["inputDigest"], [receipt])
    with TestClient(app) as client:
        response = client.post("/v1/mailroom/actions", json=commit)
    assert response.status_code == 422


def test_exact_commit_replay_returns_original_response_and_changed_replay_conflicts():
    body, private, proposed = _committable_evaluation()
    receipt = _signed_receipt(private, body["evaluationId"], proposed["inputDigest"], proposed["proposals"][0])
    commit = _commit_request(body, proposed["inputDigest"], [receipt])
    with TestClient(app) as client:
        first = client.post("/v1/mailroom/actions", json=commit)
        exact = client.post("/v1/mailroom/actions", json=commit)
        changed = dict(commit)
        changed["receipts"] = [{**receipt, "accepted": not receipt["accepted"]}]
        different = client.post("/v1/mailroom/actions", json=changed)

    assert first.status_code == exact.status_code == 200
    assert exact.json() == first.json()
    assert different.status_code == 409


def test_receipts_are_recorded_only_after_every_receipt_validates():
    body, private, proposed = _committable_evaluation(dossier_count=2)
    receipts = [
        _signed_receipt(private, body["evaluationId"], proposed["inputDigest"], proposal)
        for proposal in proposed["proposals"]
    ]
    receipts[1]["receiptSignature"] = base64.b64encode(b"invalid_signature_99999").decode()
    commit = _commit_request(body, proposed["inputDigest"], receipts)
    with TestClient(app) as client:
        response = client.post("/v1/mailroom/actions", json=commit)
    assert response.status_code == 422

    with SessionLocal() as db:
        evaluation = db.scalar(select(Evaluation).where(Evaluation.evaluation_id == body["evaluationId"]))
        assert evaluation.committed_json is None
        assert db.query(ReceiptRecord).filter(ReceiptRecord.evaluation_id == body["evaluationId"]).count() == 0
