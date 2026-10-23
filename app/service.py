import json
import uuid
from typing import Any
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .canonical import proposal_digest, sha256_hex
from .database import SessionLocal
from .decision_engine import DecisionEngine
from .models import DossierRecord, Evaluation, ReceiptRecord
from .receipt_verifier import validate_verifier, verify_receipt
from .safety import validate_proposal
from .schemas import CommitRequest, ProposeRequest


class ConflictError(Exception):
    pass


class NotFoundError(Exception):
    pass


class MailroomService:
    def __init__(self, engine: DecisionEngine | None = None):
        self.engine = engine or DecisionEngine()

    def propose(self, request: ProposeRequest) -> dict[str, Any]:
        raw = request.model_dump(mode="json")
        validate_verifier(raw["receiptVerifier"])
        digest = sha256_hex(raw["dossiers"])

        with SessionLocal() as db:
            existing = db.scalar(select(Evaluation).where(Evaluation.evaluation_id == request.evaluationId))
            if existing:
                if existing.input_digest != digest:
                    raise ConflictError("evaluationId reused with changed content")
                return json.loads(existing.response_json)

            proposals = []
            allowed = set(request.allowedActions)

            for dossier in request.dossiers:
                d = dossier.model_dump(mode="json")
                fingerprint = sha256_hex(d)

                record = db.scalar(select(DossierRecord).where(DossierRecord.fingerprint == fingerprint))
                if record:
                    proposal = json.loads(record.proposal_json)
                    if proposal["dossierId"] != d["dossierId"]:
                        proposal = {**proposal, "dossierId": d["dossierId"]}
                else:
                    call_id = "call-" + uuid.uuid5(uuid.NAMESPACE_URL, fingerprint).hex
                    proposal = self.engine.decide(d, allowed, call_id)
                    validate_proposal(proposal, d, allowed)
                    db.add(DossierRecord(
                        fingerprint=fingerprint,
                        dossier_id=d["dossierId"],
                        proposal_json=json.dumps(proposal, separators=(",", ":")),
                    ))
                proposals.append(proposal)

            response = {
                "profile": request.profile,
                "evaluationId": request.evaluationId,
                "status": "awaiting_receipts",
                "inputDigest": digest,
                "proposals": proposals,
            }

            db.add(Evaluation(
                evaluation_id=request.evaluationId,
                input_digest=digest,
                request_json=json.dumps(raw, separators=(",", ":")),
                response_json=json.dumps(response, separators=(",", ":")),
                verifier_json=json.dumps(raw["receiptVerifier"], separators=(",", ":")),
            ))

            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                existing = db.scalar(select(Evaluation).where(Evaluation.evaluation_id == request.evaluationId))
                if existing and existing.input_digest == digest:
                    return json.loads(existing.response_json)
                raise ConflictError("concurrent evaluation conflict")

            return response

    def commit(self, request: CommitRequest) -> dict[str, Any]:
        raw = request.model_dump(mode="json")
        fingerprint = sha256_hex(raw)

        with SessionLocal() as db:
            evaluation = db.scalar(select(Evaluation).where(Evaluation.evaluation_id == request.evaluationId))
            if not evaluation:
                raise NotFoundError("unknown evaluation")

            if evaluation.input_digest != request.inputDigest:
                raise ConflictError("inputDigest mismatch")

            if evaluation.committed_json:
                if evaluation.commit_fingerprint == fingerprint:
                    return json.loads(evaluation.committed_json)
                raise ConflictError("evaluation already committed with different receipts")

            proposals_list = json.loads(evaluation.response_json).get("proposals", [])
            proposed = {p["dossierId"]: p for p in proposals_list}

            if len(request.receipts) != len(proposed):
                raise ValueError("receipt count does not match proposals count")

            receipt_dossier_ids = {r.dossierId for r in request.receipts}
            if set(proposed.keys()) != receipt_dossier_ids:
                raise ValueError("receipt set does not match proposals")

            verifier = json.loads(evaluation.verifier_json)
            key = validate_verifier(verifier)

            outcomes = []
            receipt_records = []

            # Verify every receipt signature atomically before recording any effect
            for r in request.receipts:
                p = proposed.get(r.dossierId)
                if not p:
                    raise ValueError(f"receipt for unknown dossierId: {r.dossierId}")

                if r.callId != p["callId"] or r.action != p["action"]:
                    raise ValueError(f"receipt mismatch for dossier {r.dossierId}")

                if r.proposalDigest != proposal_digest(p):
                    raise ValueError(f"receipt proposalDigest does not match normalized proposal for dossier {r.dossierId}")

                r_dict = r.model_dump(mode="json")
                if not verify_receipt(key, request.evaluationId, request.inputDigest, r_dict):
                    raise ValueError(f"invalid Ed25519 signature for receipt {r.receiptId}")

                status = "executed" if r.accepted else "rejected"
                receipt_records.append(ReceiptRecord(
                    evaluation_id=request.evaluationId,
                    dossier_id=r.dossierId,
                    call_id=r.callId,
                    receipt_id=r.receiptId,
                    accepted=r.accepted,
                    outcome=status,
                ))
                outcomes.append({
                    "dossierId": r.dossierId,
                    "callId": r.callId,
                    "action": r.action,
                    "proposalDigest": r.proposalDigest,
                    "receiptId": r.receiptId,
                    "status": status,
                })

            response = {
                "profile": request.profile,
                "evaluationId": request.evaluationId,
                "status": "completed",
                "inputDigest": request.inputDigest,
                "outcomes": outcomes,
            }

            evaluation.committed_json = json.dumps(response, separators=(",", ":"))
            evaluation.commit_fingerprint = fingerprint
            db.add_all(receipt_records)

            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                existing = db.scalar(select(Evaluation).where(Evaluation.evaluation_id == request.evaluationId))
                if existing and existing.committed_json:
                    if existing.commit_fingerprint == fingerprint:
                        return json.loads(existing.committed_json)
                    raise ConflictError("evaluation already committed with different receipts")
                raise

            return response
