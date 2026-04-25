from __future__ import annotations
import json
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common.constants import GCM_IV_SIZE

class StorageError(Exception):
    pass

def _encrypt_file(key: bytes, path: Path, plaintext: bytes) -> None:
    iv = os.urandom(GCM_IV_SIZE)
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(iv + ct)
    tmp.replace(path)

def _decrypt_file(key: bytes, path: Path) -> bytes:
    raw = path.read_bytes()
    if len(raw) < GCM_IV_SIZE + 16:
        raise StorageError(f"arquivo cifrado corrompido: {path}")
    iv, ct = raw[:GCM_IV_SIZE], raw[GCM_IV_SIZE:]
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
