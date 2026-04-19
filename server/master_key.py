"""Deriva a chave mestre do servidor a partir da senha do operador e do master.salt."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from common.constants import AES_KEY_SIZE, PBKDF2_ITERATIONS, SALT_SIZE


def load_or_create_master_salt(path: Path) -> bytes:
    if path.exists():
        salt = path.read_bytes()
        if len(salt) != SALT_SIZE:
            raise ValueError(f"master.salt com tamanho inesperado ({len(salt)} bytes)")
        return salt
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_SIZE)
    path.write_bytes(salt)
    return salt


def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))
