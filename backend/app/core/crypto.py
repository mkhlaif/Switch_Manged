"""Encryption of switch credentials at rest (Fernet: AES-128-CBC + HMAC-SHA256)."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class CredentialCryptoError(RuntimeError):
    pass


def generate_key() -> str:
    return Fernet.generate_key().decode()


def _fernet() -> Fernet:
    key = get_settings().credential_encryption_key
    if not key:
        raise CredentialCryptoError(
            "CREDENTIAL_ENCRYPTION_KEY is not set. Generate one with 'python -m app.cli generate-key'."
        )
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise CredentialCryptoError("CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key.") from exc


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise CredentialCryptoError(
            "Stored credential cannot be decrypted (wrong CREDENTIAL_ENCRYPTION_KEY?)."
        ) from exc


def check_key_configured() -> None:
    """Fail fast at startup if the key is missing or malformed."""
    _fernet()
