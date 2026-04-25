import pytest
from server.blockchain import ChainError, make_block, make_genesis, validate_chain

def _build_chain():
    g = make_genesis()
    b1 = make_block(1, "alice", b"\x00" * 12, b"ct1", g.hash)
    b2 = make_block(2, "bob", b"\x01" * 12, b"ct2", b1.hash)
    return [g, b1, b2]

def test_validacao_cadeia_ok():
    validate_chain(_build_chain())

def test_validacao_cadeia_prev_hash_invalido():
    chain = _build_chain()
    bad_prev = bytearray(chain[1].prev_hash)
    bad_prev[0] ^= 1
    chain[1] = chain[1].__class__(
        index=chain[1].index,
        timestamp=chain[1].timestamp,
        owner=chain[1].owner,
        iv=chain[1].iv,
        payload=chain[1].payload,
        prev_hash=bytes(bad_prev),
        hash=chain[1].hash,
    )
    with pytest.raises(ChainError, match="prev_hash"):
        validate_chain(chain)

def test_validacao_cadeia_hash_inconsistente():
    chain = _build_chain()
    chain[2] = chain[2].__class__(
        index=chain[2].index,
        timestamp=chain[2].timestamp,
        owner=chain[2].owner,
        iv=chain[2].iv,
        payload=b"adulterado",
        prev_hash=chain[2].prev_hash,
        hash=chain[2].hash,
    )
    with pytest.raises(ChainError, match="hash"):
        validate_chain(chain)
