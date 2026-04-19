"""Sessão do cliente: socket + fluxo de registro/login + operações de bloco.

O objeto `ClientSession` guarda em MEMÓRIA (nunca em disco ou global):
- enc_key (derivada da senha) — nunca sai do processo
- session_token (emitido pelo servidor) — autorização em operações
- username
"""

from __future__ import annotations

import base64
import socket
from dataclasses import dataclass
from typing import Any

from client.crypto import (
    UserKeys,
    challenge_response,
    decrypt_block,
    derive_user_keys,
    encrypt_block,
    new_salt,
    new_totp_secret,
)
from common.constants import HOST, PORT, TOTP_DIGITS, TOTP_INTERVAL
from common.protocol import ProtocolError, b64d, b64e, recv_response, send_message


@dataclass
class SessionInfo:
    """Estado da sessão ativa no cliente.

    `enc_key` é a **chave de sessão** do enunciado: derivada via PBKDF2 no momento do
    login, mantida apenas na memória do processo cliente, usada para cifrar/decifrar
    o payload dos blocos deste usuário. Nunca é escrita em disco nem trafega na rede.
    """

    username: str
    token: str
    enc_key: bytes

    @property
    def session_key(self) -> bytes:
        """Alias semântico: mesma `enc_key`, renomeada para casar com o enunciado."""
        return self.enc_key


class ClientError(Exception):
    pass


class Client:
    def __init__(self, host: str = HOST, port: int = PORT) -> None:
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.session: SessionInfo | None = None

    # ---------- conexão ----------

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.session = None

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.logout()
        finally:
            self.close()

    def _call(self, op: str, data: dict) -> dict:
        if self.sock is None:
            raise ClientError("nao conectado")
        send_message(self.sock, op, data)
        ok, payload, err = recv_response(self.sock)
        if not ok:
            raise ClientError(err or "erro sem descricao")
        return payload

    # ---------- registro ----------

    def register(self, username: str, password: str) -> tuple[str, str]:
        """Gera salt, totp_secret, deriva auth_key e registra. Retorna (segredo_b32, otpauth_uri)."""
        salt = new_salt()
        totp_secret = new_totp_secret()
        keys = derive_user_keys(password, salt)
        self._call(
            "REGISTER",
            {
                "username": username,
                "salt_kdf": b64e(salt),
                "auth_key": b64e(keys.auth_key),
                "totp_secret": b64e(totp_secret),
            },
        )
        secret_b32 = base64.b32encode(totp_secret).decode("ascii").rstrip("=")
        otpauth = (
            f"otpauth://totp/MiniBlockchain:{username}?secret={secret_b32}"
            f"&issuer=MiniBlockchain&digits={TOTP_DIGITS}&period={TOTP_INTERVAL}"
        )
        return secret_b32, otpauth

    # ---------- login ----------

    def login(self, username: str, password: str, totp_code: str) -> SessionInfo:
        hello = self._call("HELLO", {"username": username})
        salt = b64d(hello["salt_kdf"])
        nonce = b64d(hello["nonce"])
        keys: UserKeys = derive_user_keys(password, salt)
        resp = challenge_response(keys.auth_key, nonce)
        auth_reply = self._call(
            "AUTH",
            {"response": b64e(resp), "totp_code": totp_code},
        )
        self.session = SessionInfo(
            username=auth_reply["username"],
            token=auth_reply["session_token"],
            enc_key=keys.enc_key,
        )
        return self.session

    def logout(self) -> None:
        if self.session is None:
            return
        try:
            self._call("LOGOUT", {"session_token": self.session.token})
        except (ClientError, ProtocolError):
            pass
        self.session = None

    # ---------- blocos ----------

    def add_block(self, data: bytes) -> dict:
        if self.session is None:
            raise ClientError("faca login primeiro")
        # Precisamos do índice do próximo bloco para amarrar ao AAD. Buscamos via LIST.
        listing = self._call("LIST", {"session_token": self.session.token})
        next_index = len(listing["blocks"])
        iv, payload = encrypt_block(self.session.enc_key, self.session.username, next_index, data)
        return self._call(
            "ADDBLOCK",
            {
                "session_token": self.session.token,
                "iv": b64e(iv),
                "payload": b64e(payload),
            },
        )

    def list_chain(self) -> dict:
        if self.session is None:
            raise ClientError("faca login primeiro")
        return self._call("LIST", {"session_token": self.session.token})

    def decrypt_mine(self, blocks: list[dict]) -> list[dict]:
        """Decifra blocos pertencentes ao usuário atual. Devolve lista com campo 'plaintext' ou 'error'."""
        if self.session is None:
            raise ClientError("faca login primeiro")
        out: list[dict] = []
        for b in blocks:
            entry: dict[str, Any] = {"index": b["index"], "owner": b["owner"], "timestamp": b["timestamp"]}
            if b["owner"] != self.session.username:
                entry["plaintext"] = None
                entry["note"] = "bloco de outro usuario (nao decifravel)"
            else:
                try:
                    pt = decrypt_block(
                        self.session.enc_key,
                        b["owner"],
                        int(b["index"]),
                        b64d(b["iv"]),
                        b64d(b["payload"]),
                    )
                    entry["plaintext"] = pt.decode("utf-8", errors="replace")
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = f"falha de integridade (AES-GCM): {exc.__class__.__name__}"
            out.append(entry)
        return out

    # ---------- demo ----------

    def tamper(self, index: int, mode: str) -> dict:
        if self.session is None:
            raise ClientError("faca login primeiro")
        return self._call(
            "TAMPER",
            {"session_token": self.session.token, "index": index, "mode": mode},
        )

    def logs(self, tail: int = 50) -> list[str]:
        if self.session is None:
            raise ClientError("faca login primeiro")
        reply = self._call("LOGS", {"session_token": self.session.token, "tail": tail})
        return reply.get("lines", [])
