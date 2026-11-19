"""Cryptographic core for py-crypto-vault.

File format (documented spec):

    [4 bytes]  format version (0x01, big-endian)
    [16 bytes] Argon2id salt
    [16 bytes] AES-GCM nonce
    [16 bytes] AES-GCM authentication tag
    [N bytes]  ciphertext
"""

import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

logger = logging.getLogger(__name__)

FORMAT_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 16
MEMORY_COST = 64 * 1024  # 64 MiB
TIME_COST = 3
PARALLELISM = 4


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using Argon2id."""
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=TIME_COST,
        lanes=PARALLELISM,
        memory_cost=MEMORY_COST,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Encrypt ``input_path`` and write the vault to ``output_path``.

    Raises:
        FileNotFoundError: if ``input_path`` does not exist.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)

    plaintext = input_path.read_bytes()
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    output_path.write_bytes(
        FORMAT_VERSION.to_bytes(4, "big") + salt + nonce + ciphertext_with_tag
    )
    logger.info(
        "Encrypted %s -> %s (%d bytes)",
        input_path,
        output_path,
        output_path.stat().st_size,
    )


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    """Decrypt ``input_path`` (vault format) and write plaintext to ``output_path``.

    Raises:
        FileNotFoundError: if ``input_path`` does not exist.
        ValueError: if the password is wrong or the file is corrupted/tampered.
    """
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    data = input_path.read_bytes()

    if len(data) < 4 + SALT_LEN + NONCE_LEN + TAG_LEN:
        raise ValueError("File too short to be a valid vault")

    version = int.from_bytes(data[:4], "big")
    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported vault format version: {version}")

    salt = data[4 : 4 + SALT_LEN]
    nonce = data[4 + SALT_LEN : 4 + SALT_LEN + NONCE_LEN]
    tag_and_ciphertext = data[4 + SALT_LEN + NONCE_LEN :]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, tag_and_ciphertext, None)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Decryption failed: wrong password or corrupted file") from exc

    output_path.write_bytes(plaintext)
    logger.info(
        "Decrypted %s -> %s (%d bytes)", input_path, output_path, len(plaintext)
    )
