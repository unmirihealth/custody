from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from custody.audit import keys


def test_generate_and_save_writes_a_loadable_key(tmp_path: Path) -> None:
    path = tmp_path / "signing_key.pem"
    key = keys.generate_and_save(path)
    assert path.exists()
    assert isinstance(key, Ed25519PrivateKey)

    loaded = keys.load(path)
    # Same key: signs match when verified with the same public key.
    sig = key.sign(b"test payload")
    loaded.public_key().verify(sig, b"test payload")


def test_file_permissions_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "signing_key.pem"
    keys.generate_and_save(path)
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_refuses_to_overwrite_existing_key(tmp_path: Path) -> None:
    path = tmp_path / "signing_key.pem"
    keys.generate_and_save(path)
    with pytest.raises(FileExistsError):
        keys.generate_and_save(path)


def test_public_key_hex_round_trips(tmp_path: Path) -> None:
    key = keys.generate_and_save(tmp_path / "k.pem")
    hex_pub = keys.public_key_hex(key)
    pub = keys.public_key_from_hex(hex_pub)
    sig = key.sign(b"hello")
    pub.verify(sig, b"hello")  # does not raise


def test_load_rejects_non_ed25519_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = tmp_path / "rsa_key.pem"
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="not an Ed25519"):
        keys.load(path)
