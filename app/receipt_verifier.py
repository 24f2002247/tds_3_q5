import base64
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import canonical_bytes


def _b64url(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def validate_verifier(verifier: dict[str, Any]) -> Ed25519PublicKey:
    if not isinstance(verifier, dict):
        raise ValueError("receiptVerifier must be an object")
    if verifier.get("algorithm") != "Ed25519":
        raise ValueError("unsupported receiptVerifier algorithm; expected Ed25519")
    jwk = verifier.get("publicKeyJwk", {})
    if not isinstance(jwk, dict):
        raise ValueError("publicKeyJwk must be an object")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("invalid Ed25519 JWK parameters")
    x_val = jwk.get("x", "")
    if not isinstance(x_val, str) or not x_val:
        raise ValueError("missing public key x coordinate")
    try:
        raw_key = _b64url(x_val)
        key = Ed25519PublicKey.from_public_bytes(raw_key)
        if len(key.public_bytes(Encoding.Raw, PublicFormat.Raw)) != 32:
            raise ValueError("invalid public key length")
        return key
    except Exception as exc:
        raise ValueError(f"invalid Ed25519 public key: {exc}") from exc


def verify_receipt(
    verifier: dict[str, Any] | Ed25519PublicKey,
    evaluation_id: str,
    input_digest: str,
    receipt: dict[str, Any],
) -> bool:
    try:
        if isinstance(verifier, Ed25519PublicKey):
            key = verifier
        else:
            key = validate_verifier(verifier)

        sig_raw = receipt.get("receiptSignature", "")
        if not isinstance(sig_raw, str) or not sig_raw:
            return False
        # Decode signature (handle standard or url-safe base64 padding)
        pad = "=" * (-len(sig_raw) % 4)
        sig_bytes = base64.b64decode(sig_raw + pad)

        # The inner receipt contains every receipt field except receiptSignature
        inner_receipt = {k: v for k, v in receipt.items() if k != "receiptSignature"}
        message = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": evaluation_id,
            "inputDigest": input_digest,
            "receipt": inner_receipt,
        }
        key.verify(sig_bytes, canonical_bytes(message))
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature, Exception):
        return False
