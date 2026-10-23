import uuid
from fastapi.testclient import TestClient

from app.main import app
from .test_api import request_body


def test_evaluation_content_conflict():
    eval_id = "conflict-test-" + uuid.uuid4().hex
    body = request_body(eval_id)
    with TestClient(app) as client:
        assert client.post("/v1/mailroom/actions", json=body).status_code == 200
        changed = request_body(eval_id)
        changed["dossiers"][0]["objective"] = "changed content to trigger conflict"
        assert client.post("/v1/mailroom/actions", json=changed).status_code == 409


def test_unknown_commit_is_rejected():
    eval_id = "unknown-commit-" + uuid.uuid4().hex
    body = request_body(eval_id)
    body.update({"operation": "commit", "inputDigest": "0" * 64, "receipts": []})
    with TestClient(app) as client:
        assert client.post("/v1/mailroom/actions", json=body).status_code in (404, 422)
