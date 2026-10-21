from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.policy import PolicyBundleError, PolicyEngine, bundle_path_for, sign_policy
from custody.policy.bundle import verify_policy_bundle


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text("rules:\n  - id: a\n    when: { tool: catalog.list }\n    decision: allow\n"
                     "default: deny\nmodel_allowlist: {}\n")
    return path


class TestSignAndVerify:
    def test_freshly_signed_bundle_verifies(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        verify_policy_bundle(policy_file, bundle)  # must not raise

    def test_bundle_path_for_follows_convention(self, policy_file: Path) -> None:
        assert bundle_path_for(policy_file) == policy_file.with_name("policy.yaml.sig.json")

    def test_edited_file_fails_verification(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        policy_file.write_text(policy_file.read_text() + "\n# a trailing comment\n")
        with pytest.raises(PolicyBundleError, match="has changed since it was signed"):
            verify_policy_bundle(policy_file, bundle)

    def test_bundle_signed_by_a_different_key_fails(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        # Swap in a different public key but keep the (now mismatched)
        # signature: simulates a tampered-with bundle file, not just a
        # tampered-with policy file.
        from custody.audit.keys import public_key_hex

        other_key_hex = public_key_hex(Ed25519PrivateKey.generate())
        tampered = bundle.model_copy(update={"public_key": other_key_hex})
        with pytest.raises(PolicyBundleError, match="does not verify"):
            verify_policy_bundle(policy_file, tampered)

    def test_round_trips_through_json(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        from custody.policy import SignedPolicyBundle

        restored = SignedPolicyBundle.model_validate_json(bundle.model_dump_json())
        verify_policy_bundle(policy_file, restored)  # must not raise


class TestLoadVerified:
    def test_loads_when_bundle_is_valid(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        bundle_path_for(policy_file).write_text(bundle.model_dump_json())
        engine = PolicyEngine.load_verified(policy_file)
        assert engine.policy.default.value == "deny"

    def test_raises_when_no_bundle_present(self, policy_file: Path) -> None:
        with pytest.raises(PolicyBundleError, match="no signed bundle"):
            PolicyEngine.load_verified(policy_file)

    def test_raises_when_file_changed_after_signing(self, policy_file: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        bundle_path_for(policy_file).write_text(bundle.model_dump_json())
        policy_file.write_text(policy_file.read_text() + "\n# tampered\n")
        with pytest.raises(PolicyBundleError, match="has changed since it was signed"):
            PolicyEngine.load_verified(policy_file)

    def test_accepts_an_explicit_bundle_path(self, policy_file: Path, tmp_path: Path) -> None:
        bundle = sign_policy(policy_file, Ed25519PrivateKey.generate())
        custom = tmp_path / "elsewhere.json"
        custom.write_text(bundle.model_dump_json())
        engine = PolicyEngine.load_verified(policy_file, bundle_path=custom)
        assert engine.policy.default.value == "deny"
