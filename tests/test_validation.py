import pytest
from pydantic import ValidationError

from app.schemas import ProposeRequest


def test_duplicate_dossier_ids_rejected():
    base = {
        "profile": "ga5-mailroom-action-gate/v2",
        "operation": "propose",
        "evaluationId": "eval-1",
        "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "AA"}},
        "corpus": {"coreId": "c", "auditId": "a", "stableCount": 58, "freshCount": 6},
        "allowedActions": ["create_draft", "update_internal_record", "send_approved_notice", "request_confirmation", "quarantine_item", "no_action"],
        "dossiers": [
            {
                "dossierId": "duplicate-id",
                "partition": "stable_core",
                "receivedAt": "2026-10-22T10:00:00Z",
                "mailbox": "support@example.com",
                "objective": "First",
                "sources": [{"sourceId": "s1", "kind": "email", "provenance": "customer", "title": "T1", "lines": [{"lineId": "l1", "text": "A"}]}],
            },
            {
                "dossierId": "duplicate-id",
                "partition": "stable_core",
                "receivedAt": "2026-10-22T10:00:00Z",
                "mailbox": "support@example.com",
                "objective": "Second",
                "sources": [{"sourceId": "s2", "kind": "email", "provenance": "customer", "title": "T2", "lines": [{"lineId": "l2", "text": "B"}]}],
            },
        ],
    }
    with pytest.raises(ValidationError):
        ProposeRequest.model_validate(base)
