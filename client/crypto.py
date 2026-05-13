# Feito por Eduardo Boçon e Jiliard Peifer

from __future__ import annotations
import hmac
import os
import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from common.constants import (
    AES_KEY_SIZE,
    BLOCK_AAD_PREFIX,
    GCM_IV_SIZE,
    IV_PBKDF2_ITERATIONS,
    IV_SALT_SIZE,
    LOGIN_CONTEXT,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    TOTP_SECRET_BYTES,
)

@dataclass
class UserKeys:
    auth_key: bytes
    enc_key: bytes

def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def new_totp_secret() -> bytes:
    return secrets.token_bytes(TOTP_SECRET_BYTES)

def derive_user_keys(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> UserKeys:
    if len(salt) < 8:
        raise ValueError("salt muito curto")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=2 * AES_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    material = kdf.derive(password.encode("utf-8"))
    return UserKeys(auth_key=material[:AES_KEY_SIZE], enc_key=material[AES_KEY_SIZE:])

def challenge_response(auth_key: bytes, nonce: bytes) -> bytes:
    return hmac.new(auth_key, nonce + LOGIN_CONTEXT, "sha256").digest()

def _block_aad(owner: str, index: int) -> bytes:
    return BLOCK_AAD_PREFIX + b"|" + owner.encode("utf-8") + b"|" + str(index).encode("ascii")

def _derive_iv(enc_key: bytes, salt_iv: bytes) -> bytes:
    """Deriva um IV de 12 bytes via PBKDF2, usando um salt aleatório por bloco."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=GCM_IV_SIZE,
        salt=salt_iv,
        iterations=IV_PBKDF2_ITERATIONS,
    )
    return kdf.derive(enc_key)

def encrypt_block(enc_key: bytes, owner: str, index: int, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    salt_iv = os.urandom(IV_SALT_SIZE)
    iv = _derive_iv(enc_key, salt_iv)
    aesgcm = AESGCM(enc_key)
    ct = aesgcm.encrypt(iv, plaintext, _block_aad(owner, index))
    return salt_iv, iv, ct

def decrypt_block(enc_key: bytes, owner: str, index: int, salt_iv: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    expected_iv = _derive_iv(enc_key, salt_iv)
    if expected_iv != iv:
        raise ValueError("IV inconsistente com salt_iv (possivel adulteracao)")
    aesgcm = AESGCM(enc_key)
    return aesgcm.decrypt(iv, ciphertext, _block_aad(owner, index))
