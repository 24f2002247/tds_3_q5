import hashlib
import json
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 bytes of data encoded as recursively key-sorted compact JSON."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Lowercase SHA-256 hex string over canonical bytes."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def proposal_for_digest(proposal: dict[str, Any]) -> dict[str, Any]:
    """
    Normalized proposal view for proposalDigest:
    keep exactly dossierId, callId, action, target (null when absent),
    payload, and evidence (sorted list of strings).
    """
    target = proposal.get("target")
    evidence = sorted(proposal.get("evidence", []))
    return {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": target if target is not None else None,
        "payload": proposal["payload"],
        "evidence": evidence,
    }


def proposal_digest(proposal: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of the normalized proposal."""
    return sha256_hex(proposal_for_digest(proposal))
