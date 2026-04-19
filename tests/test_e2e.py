"""Testes ponta-a-ponta via TCP real (servidor em thread + cliente socket)."""

from __future__ import annotations

import base64

import pyotp
import pytest

from client.session import Client, ClientError


def _totp_of(secret_b32: str) -> str:
    return pyotp.TOTP(secret_b32).now()


def test_registro_login_add_list(server):
    c = Client(server["host"], server["port"])
    c.connect()
    try:
        secret_b32, _uri = c.register("alice", "senhaforte1")
        c.login("alice", "senhaforte1", _totp_of(secret_b32))
        c.add_block(b"minha transacao")
        reply = c.list_chain()
        assert reply["chain_ok"] is True
        assert len(reply["blocks"]) == 2  # genesis + 1
        decoded = c.decrypt_mine(reply["blocks"])
        assert decoded[1]["plaintext"] == "minha transacao"
    finally:
        c.close()


def test_multiusuario_isolamento(server):
    a = Client(server["host"], server["port"])
    b = Client(server["host"], server["port"])
    a.connect()
    b.connect()
    try:
        a_secret, _ = a.register("alice", "pwA")
        b_secret, _ = b.register("bob", "pwB")
        a.login("alice", "pwA", _totp_of(a_secret))
        a.add_block(b"dado de alice")
        a.logout()
        b.login("bob", "pwB", _totp_of(b_secret))
        b.add_block(b"dado de bob")
        reply = b.list_chain()
        assert reply["chain_ok"] is True
        decoded = b.decrypt_mine(reply["blocks"])
        plaintexts = {e["index"]: e for e in decoded}
        assert plaintexts[1]["plaintext"] is None  # bloco da alice — opaco pra bob
        assert plaintexts[2]["plaintext"] == "dado de bob"
    finally:
        a.close()
        b.close()


def test_login_senha_errada(server):
    c = Client(server["host"], server["port"])
    c.connect()
    try:
        secret, _ = c.register("carol", "certo")
        with pytest.raises(ClientError, match="credenciais"):
            c.login("carol", "errado", _totp_of(secret))
    finally:
        c.close()


def test_login_totp_errado(server):
    c = Client(server["host"], server["port"])
    c.connect()
    try:
        c.register("dave", "pw")
        with pytest.raises(ClientError, match="credenciais"):
            c.login("dave", "pw", "000000")
    finally:
        c.close()


def test_tamper_ciphertext_detectado(server):
    c = Client(server["host"], server["port"])
    c.connect()
    try:
        secret, _ = c.register("eve", "pw")
        c.login("eve", "pw", _totp_of(secret))
        c.add_block(b"conteudo original")
        c.tamper(1, "ciphertext")
        reply = c.list_chain()
        # hash do bloco não foi recalculado pelo TAMPER -> a chain fica inválida (hash do bloco não bate).
        assert reply["chain_ok"] is False
        decoded = c.decrypt_mine(reply["blocks"])
        assert "error" in decoded[1]
    finally:
        c.close()


def test_tamper_prev_hash_detectado(server):
    c = Client(server["host"], server["port"])
    c.connect()
    try:
        secret, _ = c.register("frank", "pw")
        c.login("frank", "pw", _totp_of(secret))
        c.add_block(b"a")
        c.add_block(b"b")
        c.tamper(2, "prev_hash")
        reply = c.list_chain()
        assert reply["chain_ok"] is False
        assert "prev_hash" in (reply["chain_error"] or "") or "hash" in (reply["chain_error"] or "")
    finally:
        c.close()
