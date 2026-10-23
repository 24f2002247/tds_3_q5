import base64
import json
import re
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app.main import app


def request_body(evaluation_id: str | None = None):
    if evaluation_id is None:
        evaluation_id = "api-test-" + uuid.uuid4().hex
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    dossier = {
        "dossierId": f"d-{evaluation_id}",
        "partition": "fresh_audit",
        "receivedAt": "2026-10-22T10:00:00Z",
        "mailbox": "support@example.com",
        "objective": "Help with an order",
        "sources": [
            {
                "sourceId": "s1",
                "kind": "email",
                "provenance": "customer",
                "title": "Customer Inquiry",
                "lines": [{"lineId": "l1", "text": "Please check status of order ORD-9988"}],
            }
        ],
    }
    body = {
        "profile": "ga5-mailroom-action-gate/v2",
        "operation": "propose",
        "evaluationId": evaluation_id,
        "receiptVerifier": {
            "algorithm": "Ed25519",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
            },
        },
        "corpus": {"coreId": "c", "auditId": "a", "stableCount": 58, "freshCount": 6},
        "allowedActions": [
            "create_draft",
            "update_internal_record",
            "send_approved_notice",
            "request_confirmation",
            "quarantine_item",
            "no_action",
        ],
        "dossiers": [dossier],
    }
    return body


def test_propose_and_exact_replay():
    body = request_body()
    with TestClient(app) as client:
        first = client.post("/v1/mailroom/actions", json=body)
        second = client.post("/v1/mailroom/actions", json=body)
        root = client.post("/", json=body)
        mailroom = client.post("/mailroom", json=body)

    assert first.status_code == second.status_code == root.status_code == mailroom.status_code == 200
    assert first.json() == second.json() == root.json() == mailroom.json()
    assert first.json()["status"] == "awaiting_receipts"


def test_unknown_operation_and_malformed_json():
    with TestClient(app) as client:
        assert client.post("/v1/mailroom/actions", json={"operation": "unknown"}).status_code == 400
        assert client.post("/v1/mailroom/actions", content=b"{not-json", headers={"content-type": "application/json"}).status_code == 422


def _resolve_ref(ref: str, spec: dict) -> dict:
    assert ref.startswith("#/"), f"only document-root refs supported, got: {ref!r}"
    parts = ref.lstrip("#/").split("/")
    node = spec
    for part in parts:
        assert part in node, f"ref segment {part!r} not found; available: {list(node.keys())}"
        node = node[part]
    return node


def test_openapi_actions_endpoint_has_request_body():
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    post = spec["paths"]["/v1/mailroom/actions"]["post"]
    assert "requestBody" in post, "POST /v1/mailroom/actions must declare a requestBody"

    content = post["requestBody"]["content"]
    assert "application/json" in content, "requestBody must include application/json content"

    schema = content["application/json"]["schema"]
    assert "oneOf" in schema, "schema must use oneOf to cover propose and commit"
    assert len(schema["oneOf"]) == 2, "oneOf must have exactly two variants"

    operations = set()
    for variant in schema["oneOf"]:
        assert "$ref" in variant, f"expected a $ref variant, got: {variant}"
        resolved = _resolve_ref(variant["$ref"], spec)
        props = resolved.get("properties", {})
        assert "operation" in props, f"resolved schema missing 'operation': {list(props.keys())}"
        op_val = props["operation"].get("const") or props["operation"].get("enum")
        if isinstance(op_val, list):
            operations.update(op_val)
        elif op_val is not None:
            operations.add(op_val)

    assert "propose" in operations, "propose not found across oneOf variants"
    assert "commit" in operations, "commit not found across oneOf variants"


def test_openapi_nested_refs_resolve_in_components():
    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()

    components_schemas = spec.get("components", {}).get("schemas", {})
    raw = json.dumps(components_schemas)

    refs = re.findall(r'"\$ref":\s*"([^"]+)"', raw)
    assert refs, "expected at least some $refs inside components/schemas"

    for ref in refs:
        assert ref.startswith("#/components/schemas/"), f"ref {ref!r} does not point to #/components/schemas/"
        model_name = ref.split("/")[-1]
        assert model_name in components_schemas, f"$ref target {ref!r} not found in components/schemas"

    for expected in ("Dossier", "Source", "Line", "Verifier", "Corpus", "Receipt"):
        assert expected in components_schemas, f"{expected} missing from components/schemas"
