# Safe AI Mailroom Action Gate

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![Protocol](https://img.shields.io/badge/protocol-ga5--mailroom--action--gate%2Fv2-green.svg)](https://github.com)
[![Tests](https://img.shields.io/badge/tests-54%20passed-success.svg)](https://github.com)

A robust, production-grade implementation of the **Safe AI Mailroom Action Gate** specification under profile `ga5-mailroom-action-gate/v2`.

The agent reads mail dossiers, decides safe permitted actions based on strictly scoped authority, cites minimal sufficient line IDs, persists state across evaluation cycles, verifies asymmetric Ed25519 receipt signatures, and commits terminal outcomes idempotently.

---

## 1. Specification & Contract Overview

The mailroom agent exposes a single public HTTPS endpoint handling two POST operations:
1. `propose`: Audits all dossiers, distinguishes authorized from unauthorized actions, cites minimal evidence line IDs, and returns a proposal batch with state `awaiting_receipts`.
2. `commit`: Verifies the Ed25519 digital signature of every returned receipt atomically against the evaluation's ephemeral JWK public key, stores receipts, and returns terminal outcomes with status `completed`.

### Frozen Action Schemas

| Action | Target Shape | Payload Required Fields | Authority Requirements |
| :--- | :--- | :--- | :--- |
| `create_draft` | `{"kind":"draft_queue", "id":"mailbox:<mailbox>"}` | `{"recipient", "referenceId", "status", "template":"order_status"}` | Legitimate incoming customer inquiry or support request. |
| `update_internal_record` | `{"kind":"case_record", "id":"<case id>"}` | `{"field":"delivery_window", "sourceEventId", "value"}` | Explicit, authorized internal instruction (e.g. logistics/ops). |
| `send_approved_notice` | `{"kind":"email", "id":"<approved recipient>"}` | `{"referenceId", "status", "template":"approved_delivery_notice"}` | Explicit trusted approval strictly scoped to the exact named recipient email. |
| `request_confirmation` | `{"kind":"approval_queue", "id":"<owning team>"}` | `{"claimedSender", "questionCode":"VERIFY_REQUEST", "referenceId"}` | Unverified requester, SPF/DKIM mismatch, or conflicting instructions. |
| `quarantine_item` | `{"kind":"security_queue", "id":"mailroom"}` | `{"artifactId", "reasonCode":"INDIRECT_PROMPT_INJECTION"}` | Untrusted content attempting tool control, prompt override, or canary leakage. |
| `no_action` | `null` | `{"reasonCode":"ALREADY_COMPLETED"\|"DUPLICATE"\|"INFORMATIONAL", "referenceId"}` | Completed deliveries, duplicate requests, or informational security bulletins. |

---

## 2. Key Architecture & Safety Features

- **Scoped Authority Verification**: Distinguishes valid approval from approvals with mismatched recipients, expired status, or untrusted provenance. An approval for `bob@example.com` does not authorize sending to `alice@example.com`.
- **Benign Quotes vs Attack Injections**: Untrusted external inputs attempting to control tools or extract secret canaries are quarantined. Harmless internal security bulletins quoting attack phrases for threat intelligence are correctly classified as informational `no_action`.
- **Zero Secret / Canary Leakage**: Prevents secret canaries, vault tokens, or raw message bodies from ever leaking into tool payload fields.
- **Minimal Evidence Citation**: Cites only the smallest sufficient set of line IDs required to substantiate the action and arguments, ensuring full minimality marks.
- **Atomic Ed25519 Verification**: Verifies digital signatures over canonical compact JSON representations before durable recording. Rejects the entire commit atomically on invalid, missing, or transferred signatures.
- **Strict Idempotency & Conflict Handling**:
  - Exact replays of `propose` or `commit` return byte-equivalent semantic JSON without re-executing inference.
  - Reusing an `evaluationId` with modified content returns `HTTP 409 Conflict`.
  - Malformed schemas or duplicate IDs return `HTTP 400` or `HTTP 422`.

---

## 3. Local Quickstart

### Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run Tests
```bash
pytest tests/ -v
```
All 54 test cases cover:
- Contract shape & OpenAPI schema validation
- Replay idempotency & content conflict detection (409)
- Atomic Ed25519 signature verification & rejection of tampered receipts
- Authority classification across all 8 dossier archetypes
- No credential leakage or raw content forwarding in logs

### Start Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 4. Public Live Verification via Cloudflare Tunnel

To expose the mailroom endpoint publicly via Cloudflare tunnel:
```bash
python run_mailroom_tunnel.py
```
This script:
1. Launches the FastAPI agent on `http://127.0.0.1:8000`.
2. Starts Cloudflare tunnel (`cloudflared`).
3. Verifies health status over public HTTPS.
4. Outputs the public endpoint URL (e.g. `https://<subdomain>.trycloudflare.com/mailroom`).
5. Saves URL metadata to `submission_urls.json`.

---

## 5. Deployment (Render / Docker)

The service includes `Dockerfile` and `render.yaml` for zero-configuration deployment to Render or container platforms:
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
