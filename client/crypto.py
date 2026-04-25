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

def encrypt_block(enc_key: bytes, owner: str, index: int, plaintext: bytes) -> tuple[bytes, bytes]:
    """Cifra o payload do bloco. Retorna (iv, ciphertext+tag). IV novo a cada chamada."""
    iv = os.urandom(GCM_IV_SIZE)
    aesgcm = AESGCM(enc_key)
    ct = aesgcm.encrypt(iv, plaintext, _block_aad(owner, index))
    return iv, ct

def decrypt_block(enc_key: bytes, owner: str, index: int, iv: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(enc_key)
    return aesgcm.decrypt(iv, ciphertext, _block_aad(owner, index))
