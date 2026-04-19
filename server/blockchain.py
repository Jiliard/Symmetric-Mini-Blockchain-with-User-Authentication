"""Estrutura de bloco, cálculo de hash e validação da cadeia.

O servidor trata `iv` e `payload` como bytes opacos — ele não tenta decifrar.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

GENESIS_OWNER = "system"
GENESIS_PAYLOAD = b"genesis"
GENESIS_PREV_HASH = b"\x00" * 32


class ChainError(Exception):
    pass


@dataclass
class Block:
    index: int
    timestamp: str
    owner: str
    iv: bytes
    payload: bytes
    prev_hash: bytes
    hash: bytes

    def to_dict(self) -> dict:
        import base64

        d = asdict(self)
        for field in ("iv", "payload", "prev_hash", "hash"):
            d[field] = base64.b64encode(d[field]).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        import base64

        return cls(
            index=int(d["index"]),
            timestamp=d["timestamp"],
            owner=d["owner"],
            iv=base64.b64decode(d["iv"]),
            payload=base64.b64decode(d["payload"]),
            prev_hash=base64.b64decode(d["prev_hash"]),
            hash=base64.b64decode(d["hash"]),
        )


def _compute_hash(index: int, timestamp: str, owner: str, iv: bytes, payload: bytes, prev_hash: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(index.to_bytes(8, "big"))
    h.update(timestamp.encode("utf-8"))
    h.update(b"\x00")
    h.update(owner.encode("utf-8"))
    h.update(b"\x00")
    h.update(len(iv).to_bytes(2, "big"))
    h.update(iv)
    h.update(len(payload).to_bytes(4, "big"))
    h.update(payload)
    h.update(prev_hash)
    return h.digest()


def make_genesis() -> Block:
    ts = datetime.now(UTC).isoformat()
    # Genesis não é cifrado (owner=system); usa IV de 12 zeros só como marcador.
    iv = b"\x00" * 12
    prev_hash = GENESIS_PREV_HASH
    h = _compute_hash(0, ts, GENESIS_OWNER, iv, GENESIS_PAYLOAD, prev_hash)
    return Block(0, ts, GENESIS_OWNER, iv, GENESIS_PAYLOAD, prev_hash, h)


def make_block(index: int, owner: str, iv: bytes, payload: bytes, prev_hash: bytes) -> Block:
    ts = datetime.now(UTC).isoformat()
    h = _compute_hash(index, ts, owner, iv, payload, prev_hash)
    return Block(index, ts, owner, iv, payload, prev_hash, h)


def validate_chain(blocks: list[Block]) -> None:
    """Revalida ordem, prev_hash e hash de cada bloco. Levanta ChainError no primeiro problema."""
    if not blocks:
        raise ChainError("cadeia vazia (sem genesis)")
    for i, b in enumerate(blocks):
        if b.index != i:
            raise ChainError(f"indice inconsistente no bloco {i} (tem {b.index})")
        expected_prev = GENESIS_PREV_HASH if i == 0 else blocks[i - 1].hash
        if b.prev_hash != expected_prev:
            raise ChainError(f"prev_hash invalido no bloco {i}")
        recomputed = _compute_hash(b.index, b.timestamp, b.owner, b.iv, b.payload, b.prev_hash)
        if recomputed != b.hash:
            raise ChainError(f"hash do bloco {i} nao bate (conteudo adulterado)")
