"""Ed25519 keypair generation and loading for checkpoint signing.

`custody init` calls `generate_and_save` once per deployment. The
private key path is configurable (see custody.config); document key
handling clearly in docs/audit-log.md, this module does not add its own
access control beyond normal filesystem permissions.
"""

from __future__ import annotations

import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_and_save(private_key_path: Path) -> Ed25519PrivateKey:
    """Generate a new Ed25519 key and write it to `private_key_path` in
    PEM format, unencrypted, with 0600 permissions. Refuses to overwrite
    an existing key, use a new path (or delete the old one deliberately)
    to rotate.
    """
    if private_key_path.exists():
        raise FileExistsError(
            f"{private_key_path} already exists; refusing to overwrite an "
            "existing signing key. Checkpoints already on disk would stop "
            "verifying against a newly generated key."
        )
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_path.write_bytes(pem)
    private_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    return key


def load(private_key_path: Path) -> Ed25519PrivateKey:
    pem = private_key_path.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{private_key_path} is not an Ed25519 private key")
    return key


def public_key_hex(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))
