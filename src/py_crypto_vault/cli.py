"""CLI entry point for py-crypto-vault."""

from pathlib import Path

import typer

from py_crypto_vault.crypto import decrypt_file, encrypt_file

app = typer.Typer(
    help=("File vault CLI: AES-256-GCM encryption with Argon2id key derivation.")
)

_PASSWORD_OPTION = typer.Option(
    ...,
    "--password",
    "-p",
    help="Encryption password.",
    hide_input=True,
)

_INPUT_ARG = typer.Argument(..., help="File to encrypt.")
_OUTPUT_ARG = typer.Argument(..., help="Output vault file path.")
_VAULT_ARG = typer.Argument(..., help="Vault file to decrypt.")
_PLAIN_ARG = typer.Argument(..., help="Output plaintext file path.")


@app.command()
def encrypt(
    input_path: Path = _INPUT_ARG,
    output_path: Path = _OUTPUT_ARG,
    password: str = _PASSWORD_OPTION,
) -> None:
    """Encrypt a file with AES-256-GCM and Argon2id."""
    encrypt_file(input_path, output_path, password)
    typer.echo(f"Encrypted {input_path} -> {output_path}")


@app.command()
def decrypt(
    input_path: Path = _VAULT_ARG,
    output_path: Path = _PLAIN_ARG,
    password: str = _PASSWORD_OPTION,
) -> None:
    """Decrypt a vault file back to plaintext."""
    decrypt_file(input_path, output_path, password)
    typer.echo(f"Decrypted {input_path} -> {output_path}")


if __name__ == "__main__":
    app()
