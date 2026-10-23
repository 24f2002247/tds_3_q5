from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

PROFILE = "ga5-mailroom-action-gate/v2"

Action = Literal[
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Line(StrictModel):
    lineId: str = Field(min_length=1, max_length=256)
    text: str = Field(max_length=50_000)


class Source(StrictModel):
    sourceId: str = Field(min_length=1, max_length=256)
    kind: str = Field(min_length=1, max_length=256)
    provenance: str = Field(min_length=1, max_length=256)
    title: str = Field(max_length=2048)
    lines: list[Line] = Field(min_length=1)


class Dossier(StrictModel):
    dossierId: str = Field(min_length=1, max_length=256)
    partition: Literal["stable_core", "fresh_audit"]
    receivedAt: datetime | str
    mailbox: str = Field(min_length=1, max_length=512)
    objective: str = Field(max_length=50_000)
    sources: list[Source] = Field(min_length=1)


class Verifier(StrictModel):
    algorithm: Literal["Ed25519"]
    publicKeyJwk: dict[str, Any]


class Corpus(StrictModel):
    coreId: str = Field(min_length=1)
    auditId: str = Field(min_length=1)
    stableCount: int = Field(ge=0)
    freshCount: int = Field(ge=0)


class ProposeRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["propose"]
    evaluationId: str = Field(min_length=1, max_length=512)
    receiptVerifier: Verifier
    corpus: Corpus
    allowedActions: list[Action] = Field(min_length=1)
    dossiers: list[Dossier] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_dossiers(self):
        ids = [d.dossierId for d in self.dossiers]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate dossier IDs in proposal request")
        return self


class Proposal(StrictModel):
    dossierId: str = Field(min_length=1)
    callId: str = Field(min_length=12, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    action: Action
    target: dict[str, str] | None
    payload: dict[str, Any]
    evidence: list[str] = Field(min_length=1)


class Receipt(StrictModel):
    dossierId: str = Field(min_length=1)
    callId: str = Field(min_length=1)
    action: Action
    accepted: bool
    proposalDigest: str = Field(pattern=r"^[0-9a-f]{64}$")
    receiptId: str = Field(min_length=1, max_length=512)
    receiptSignature: str = Field(min_length=1)


class CommitRequest(StrictModel):
    profile: Literal[PROFILE]
    operation: Literal["commit"]
    evaluationId: str = Field(min_length=1, max_length=512)
    inputDigest: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipts: list[Receipt] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_receipts(self):
        keys = [(r.dossierId, r.callId) for r in self.receipts]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate receipts in commit request")
        receipt_ids = [r.receiptId for r in self.receipts]
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("duplicate receipt IDs in commit request")
        return self
