# py-crypto-vault

> File vault CLI: AES-256-GCM encryption with Argon2id key derivation.

[![CI](https://github.com/dblzroch/py-crypto-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/dblzroch/py-crypto-vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Encrypt and decrypt single files from the command line. Uses **AES-256-GCM** for
authenticated encryption and **Argon2id** for password-to-key derivation, so your
files are protected against tampering and brute-force attacks.

## Quickstart

```bash
# Clone
git clone https://github.com/dblzroch/py-crypto-vault.git
cd py-crypto-vault

# Install (uv)
uv sync --dev

# Encrypt a file
uv run crypto-vault encrypt secret.txt secret.enc --password "my-secret"

# Decrypt it back
uv run crypto-vault decrypt secret.enc secret.out --password "my-secret"
```

## Commands

| Command | Description |
|---|---|
| `crypto-vault encrypt <in> <out> --password <pw>` | Encrypt a file |
| `crypto-vault decrypt <in> <out> --password <pw>` | Decrypt a file |

## File format (documented spec)

```
[4 bytes]  format version (0x01)
[16 bytes] Argon2id salt
[16 bytes] AES-GCM nonce
[16 bytes] AES-GCM authentication tag
[N bytes]  ciphertext
```

## How it works

- **CLI**: [Typer](https://typer.tiangolo.com/) commands.
- **Crypto**: [cryptography](https://cryptography.io/) — AES-256-GCM + Argon2id.
- **Tests**: `pytest` with coverage gate at 80%.
- **CI**: GitHub Actions runs ruff, mypy and pytest on every push/PR.

## Tests & quality

```bash
make test      # pytest with coverage
make lint      # ruff + mypy
make fmt       # ruff format
```

## License

MIT
