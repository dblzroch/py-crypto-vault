"""Tests for py-crypto-vault crypto and CLI."""

import pytest
from typer.testing import CliRunner

from py_crypto_vault.cli import app
from py_crypto_vault.crypto import decrypt_file, encrypt_file


# ------------------------------------------------------------------
# Crypto round-trip
# ------------------------------------------------------------------
def test_encrypt_decrypt_round_trip(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sensitive data here")

    vault = tmp_path / "secret.enc"
    out = tmp_path / "secret.out"

    encrypt_file(src, vault, "correct-password")
    assert vault.exists()
    assert vault.stat().st_size > src.stat().st_size

    decrypt_file(vault, out, "correct-password")
    assert out.read_bytes() == b"sensitive data here"


def test_wrong_password_raises(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sensitive data here")

    vault = tmp_path / "secret.enc"
    encrypt_file(src, vault, "correct-password")

    out = tmp_path / "secret.out"
    with pytest.raises(ValueError, match="wrong password or corrupted"):
        decrypt_file(vault, out, "wrong-password")


def test_tampered_file_raises(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"sensitive data here")

    vault = tmp_path / "secret.enc"
    encrypt_file(src, vault, "correct-password")

    # Flip a byte in the ciphertext region
    data = bytearray(vault.read_bytes())
    data[-1] ^= 0xFF
    vault.write_bytes(bytes(data))

    out = tmp_path / "secret.out"
    with pytest.raises(ValueError, match="wrong password or corrupted"):
        decrypt_file(vault, out, "correct-password")


def test_encrypt_missing_input_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "missing.txt", tmp_path / "out.enc", "pw")


def test_decrypt_missing_input_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        decrypt_file(tmp_path / "missing.enc", tmp_path / "out.txt", "pw")


def test_decrypt_truncated_file_raises(tmp_path):
    vault = tmp_path / "short.enc"
    vault.write_bytes(b"\x00\x00\x00\x01")  # only version, no salt/nonce/tag
    out = tmp_path / "out.txt"
    with pytest.raises(ValueError):
        decrypt_file(vault, out, "pw")


def test_decrypt_unsupported_version_raises(tmp_path):
    vault = tmp_path / "v2.enc"
    # version 99 + 16 salt + 16 nonce + 16 tag (no ciphertext)
    vault.write_bytes((99).to_bytes(4, "big") + b"\x00" * 48)
    out = tmp_path / "out.txt"
    with pytest.raises(ValueError, match="Unsupported vault format version"):
        decrypt_file(vault, out, "pw")


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def test_cli_encrypt_decrypt(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"hello vault")

    vault = tmp_path / "secret.enc"
    out = tmp_path / "secret.out"

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["encrypt", str(src), str(vault), "--password", "test-pw"],
    )
    assert result.exit_code == 0
    assert "Encrypted" in result.output

    result = runner.invoke(
        app,
        ["decrypt", str(vault), str(out), "--password", "test-pw"],
    )
    assert result.exit_code == 0
    assert "Decrypted" in result.output
    assert out.read_bytes() == b"hello vault"


def test_cli_decrypt_wrong_password(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"hello vault")
    vault = tmp_path / "secret.enc"

    runner = CliRunner()
    runner.invoke(app, ["encrypt", str(src), str(vault), "--password", "pw"])

    out = tmp_path / "secret.out"
    result = runner.invoke(
        app,
        ["decrypt", str(vault), str(out), "--password", "wrong"],
    )
    assert result.exit_code == 1
