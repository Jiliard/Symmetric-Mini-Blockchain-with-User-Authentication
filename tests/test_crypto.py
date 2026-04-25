import pytest
from cryptography.exceptions import InvalidTag
from client.crypto import decrypt_block, derive_user_keys, encrypt_block, new_salt

def test_kdf_determinismo():
    salt = new_salt()
    k1 = derive_user_keys("hunter2", salt, iterations=10_000)
    k2 = derive_user_keys("hunter2", salt, iterations=10_000)
    assert k1.auth_key == k2.auth_key
    assert k1.enc_key == k2.enc_key

def test_kdf_salt_diferente_chave_diferente():
    k1 = derive_user_keys("hunter2", new_salt(), iterations=10_000)
    k2 = derive_user_keys("hunter2", new_salt(), iterations=10_000)
    assert k1.enc_key != k2.enc_key

def test_kdf_senha_diferente_chave_diferente():
    salt = new_salt()
    k1 = derive_user_keys("hunter2", salt, iterations=10_000)
    k2 = derive_user_keys("correct horse battery staple", salt, iterations=10_000)
    assert k1.enc_key != k2.enc_key

def test_aesgcm_roundtrip():
    keys = derive_user_keys("pw", new_salt(), iterations=10_000)
    iv, ct = encrypt_block(keys.enc_key, "alice", 3, b"mensagem secreta")
    pt = decrypt_block(keys.enc_key, "alice", 3, iv, ct)
    assert pt == b"mensagem secreta"

def test_aesgcm_tamper_ciphertext():
    keys = derive_user_keys("pw", new_salt(), iterations=10_000)
    iv, ct = encrypt_block(keys.enc_key, "alice", 3, b"dado")
    bad = bytearray(ct)
    bad[0] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_block(keys.enc_key, "alice", 3, iv, bytes(bad))

def test_aesgcm_tamper_aad_owner():
    keys = derive_user_keys("pw", new_salt(), iterations=10_000)
    iv, ct = encrypt_block(keys.enc_key, "alice", 3, b"dado")
    with pytest.raises(InvalidTag):
        decrypt_block(keys.enc_key, "bob", 3, iv, ct)
    with pytest.raises(InvalidTag):
        decrypt_block(keys.enc_key, "alice", 4, iv, ct)
