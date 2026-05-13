# Feito por Eduardo Boçon e Jiliard Peifer

from __future__ import annotations
import json
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from common.constants import GCM_IV_SIZE, IV_PBKDF2_ITERATIONS, IV_SALT_SIZE

class StorageError(Exception):
    pass

def _derive_iv(key: bytes, salt_iv: bytes) -> bytes:
    """Deriva um IV de 12 bytes via PBKDF2, usando um salt aleatório."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=GCM_IV_SIZE,
        salt=salt_iv,
        iterations=IV_PBKDF2_ITERATIONS,
    )
    return kdf.derive(key)

def _encrypt_file(key: bytes, path: Path, plaintext: bytes) -> None:
    salt_iv = os.urandom(IV_SALT_SIZE)      
    iv = _derive_iv(key, salt_iv)           
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(salt_iv + ct)           
    tmp.replace(path)

def _decrypt_file(key: bytes, path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) < IV_SALT_SIZE + GCM_IV_SIZE + 16:
        raise StorageError(f"arquivo cifrado corrompido: {path}")
    salt_iv = raw[:IV_SALT_SIZE]            
    ct = raw[IV_SALT_SIZE:]             
    iv = _derive_iv(key, salt_iv)           
    try:
        return AESGCM(key).decrypt(iv, ct, None)
    except InvalidTag as exc:
        raise StorageError(f"falha de integridade em {path} (senha mestre errada ou arquivo adulterado)") from exc

def load_json(key: bytes, path: Path, default):
    if not path.exists():
        return default
    return json.loads(_decrypt_file(key, path).decode("utf-8"))

def save_json(key: bytes, path: Path, obj) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    _encrypt_file(key, path, data)
