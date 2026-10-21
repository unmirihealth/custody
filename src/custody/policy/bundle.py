"""Signed policy bundles: a cryptographic attestation that "this exact
policy.yaml, byte for byte, was signed by whoever held this key." Reuses
the Ed25519 machinery from custody.audit.keys rather than inventing a
second signing scheme; a deployment can use the same key for both audit
checkpoints and policy signing, or separate keys, this module doesn't
care which.

The threat this addresses: a policy file determines everything else
Custody does (docs/policy-reference.md). A compliance reviewer who
signed off on a specific policy.yaml has no way, today, to later confirm
the file on disk is still the one they approved, short of a manual byte
diff against a copy they kept themselves. A signed bundle makes that
check a single command: `custody policy verify`.

This is a different guarantee from the audit log's hash chain
(docs/audit-log.md): that chain proves what happened was recorded
faithfully. A policy bundle proves what's *about to* happen is governed
by an approved file, checked once at load time, not continuously.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict

from custody.audit.keys import public_key_from_hex, public_key_hex


class SignedPolicyBundle(BaseModel):
    """Written alongside a policy file, conventionally as
    `<policy>.sig.json`. `policy_sha256` is over the exact bytes on disk
    at signing time, not a parsed/re-serialized form, so any byte-level
    change (including whitespace or comments) invalidates it."""

    model_config = ConfigDict(frozen=True)

    policy_sha256: str
    signed_at: datetime
    signature: str  # hex-encoded Ed25519 signature
    public_key: str  # hex-encoded Ed25519 public key


class PolicyBundleError(Exception):
    """Raised by verify_policy_bundle (or load_verified) when a bundle
    doesn't match the policy file it's supposed to cover, or its
    signature doesn't verify. Carries a human-readable reason; see
    `.reason`."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _signing_payload(policy_sha256: str, signed_at: datetime) -> bytes:
    # Deliberately NOT custody.audit.hashing.canonical_json: this is a
    # small, fixed two-field payload, not an open-ended dict, a plain
    # fixed-format string is simpler and just as unambiguous.
    return f"{policy_sha256}:{signed_at.isoformat()}".encode()


def sign_policy(policy_path: Path, signing_key: Ed25519PrivateKey) -> SignedPolicyBundle:
    """Sign the policy file currently on disk at `policy_path`. Does not
    validate the policy's own contents (use `custody.policy.check` for
    that first); signing an invalid policy just produces a bundle that
    faithfully attests to an invalid file.
    """
    policy_sha256 = _file_sha256(policy_path)
    signed_at = datetime.now(UTC)
    signature = signing_key.sign(_signing_payload(policy_sha256, signed_at))
    return SignedPolicyBundle(
        policy_sha256=policy_sha256,
        signed_at=signed_at,
        signature=signature.hex(),
        public_key=public_key_hex(signing_key),
    )


def verify_policy_bundle(policy_path: Path, bundle: SignedPolicyBundle) -> None:
    """Raises PolicyBundleError if `policy_path`'s current bytes don't
    match the bundle, or the bundle's signature doesn't verify against
    its own embedded public key. Returns (does nothing) on success.
    """
    current_sha256 = _file_sha256(policy_path)
    if current_sha256 != bundle.policy_sha256:
        raise PolicyBundleError(
            f"{policy_path} has changed since it was signed "
            f"(signed sha256 {bundle.policy_sha256}, current {current_sha256})"
        )
    try:
        public_key_from_hex(bundle.public_key).verify(
            bytes.fromhex(bundle.signature),
            _signing_payload(bundle.policy_sha256, bundle.signed_at),
        )
    except InvalidSignature as exc:
        raise PolicyBundleError(
            "signature does not verify against the bundle's public key"
        ) from exc


def bundle_path_for(policy_path: Path) -> Path:
    """The conventional sidecar path for a policy file's bundle:
    policy.yaml -> policy.yaml.sig.json."""
    return policy_path.with_name(policy_path.name + ".sig.json")
