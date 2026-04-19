"""Servidor TCP da mini-blockchain.

O servidor:
- guarda users.enc (verifier=auth_key, totp_secret, salt_kdf) e blockchain.enc (todos os blocos)
  cifrados com a chave mestre derivada da senha do operador;
- nunca recebe ou armazena a `enc_key` do usuário nem o plaintext dos blocos;
- aplica desafio-resposta HMAC + TOTP no login;
- revalida a cadeia inteira a cada ADDBLOCK e LIST.
"""

from __future__ import annotations

import argparse
import getpass
import secrets
import socket
import socketserver
import threading
from pathlib import Path

from common.constants import (
    CHALLENGE_NONCE_SIZE,
    HOST,
    PORT,
    SESSION_TOKEN_SIZE,
)
from common.protocol import ProtocolError, b64d, b64e, recv_message, send_response
from server.audit import log_event
from server.auth import verify_challenge, verify_totp
from server.blockchain import Block, ChainError, make_block, make_genesis, validate_chain
from server.master_key import derive_master_key, load_or_create_master_salt
from server.storage import StorageError, load_json, save_json

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
USERS_PATH = DATA_DIR / "users.enc"
CHAIN_PATH = DATA_DIR / "blockchain.enc"
SALT_PATH = DATA_DIR / "master.salt"
LOG_PATH = DATA_DIR / "access.log"


class ServerState:
    """Estado compartilhado entre as threads do servidor. Acesso serializado por lock."""

    def __init__(self, master_key: bytes) -> None:
        self.master_key = master_key
        self.lock = threading.Lock()
        self.users: dict = load_json(master_key, USERS_PATH, default={})
        chain_raw = load_json(master_key, CHAIN_PATH, default=None)
        if chain_raw is None:
            self.chain = [make_genesis()]
            save_json(master_key, CHAIN_PATH, [b.to_dict() for b in self.chain])
        else:
            self.chain = [Block.from_dict(b) for b in chain_raw]
            validate_chain(self.chain)
        # sessões: session_token (hex) -> {"username": str}
        self.sessions: dict[str, dict] = {}
        # desafios pendentes: conn_id -> {"username": str, "nonce": bytes}
        self.pending: dict[str, dict] = {}

    def save_users(self) -> None:
        save_json(self.master_key, USERS_PATH, self.users)

    def save_chain(self) -> None:
        save_json(self.master_key, CHAIN_PATH, [b.to_dict() for b in self.chain])


class Handler(socketserver.BaseRequestHandler):
    state: ServerState  # injetado em make_server

    def handle(self) -> None:  # noqa: C901  — dispatcher simples é mais claro inline
        conn_id = f"{self.client_address[0]}:{self.client_address[1]}:{secrets.token_hex(4)}"
        sock: socket.socket = self.request
        try:
            while True:
                try:
                    op, data = recv_message(sock)
                except ProtocolError:
                    return
                try:
                    handler = DISPATCH.get(op)
                    if handler is None:
                        send_response(sock, False, error=f"op desconhecida: {op}")
                        continue
                    handler(self.state, sock, conn_id, data, self.client_address)
                except Exception as exc:  # noqa: BLE001
                    log_event(LOG_PATH, "error", op=op, err=str(exc), peer=self.client_address[0])
                    send_response(sock, False, error=str(exc))
        finally:
            self.state.pending.pop(conn_id, None)


# ---------- handlers ----------

def handle_register(state: ServerState, sock, conn_id, data, peer):
    username = data["username"]
    salt_kdf = b64d(data["salt_kdf"])
    auth_key = b64d(data["auth_key"])
    totp_secret = b64d(data["totp_secret"])
    with state.lock:
        if username in state.users:
            log_event(LOG_PATH, "register_denied", user=username, peer=peer[0], reason="duplicate")
            send_response(sock, False, error="usuario ja existe")
            return
        state.users[username] = {
            "salt_kdf": b64e(salt_kdf),
            "auth_key": b64e(auth_key),
            "totp_secret": b64e(totp_secret),
        }
        state.save_users()
    log_event(LOG_PATH, "register_ok", user=username, peer=peer[0])
    send_response(sock, True, {"username": username})


def handle_hello(state: ServerState, sock, conn_id, data, peer):
    username = data["username"]
    user = state.users.get(username)
    if not user:
        # Responde com salt falso para não revelar quem existe.
        nonce = secrets.token_bytes(CHALLENGE_NONCE_SIZE)
        state.pending[conn_id] = {"username": username, "nonce": nonce, "unknown": True}
        send_response(sock, True, {"salt_kdf": b64e(secrets.token_bytes(16)), "nonce": b64e(nonce)})
        return
    nonce = secrets.token_bytes(CHALLENGE_NONCE_SIZE)
    state.pending[conn_id] = {"username": username, "nonce": nonce, "unknown": False}
    send_response(sock, True, {"salt_kdf": user["salt_kdf"], "nonce": b64e(nonce)})


def handle_auth(state: ServerState, sock, conn_id, data, peer):
    pending = state.pending.pop(conn_id, None)
    if not pending:
        send_response(sock, False, error="sem desafio pendente (chame HELLO antes)")
        return
    username = pending["username"]
    response = b64d(data["response"])
    totp_code = data["totp_code"]
    if pending.get("unknown"):
        log_event(LOG_PATH, "login_fail", user=username, peer=peer[0], reason="unknown_user")
        send_response(sock, False, error="credenciais invalidas")
        return
    user = state.users[username]
    auth_key = b64d(user["auth_key"])
    totp_secret = b64d(user["totp_secret"])
    if not verify_challenge(auth_key, pending["nonce"], response):
        log_event(LOG_PATH, "login_fail", user=username, peer=peer[0], reason="bad_password")
        send_response(sock, False, error="credenciais invalidas")
        return
    if not verify_totp(totp_secret, totp_code):
        log_event(LOG_PATH, "login_fail", user=username, peer=peer[0], reason="bad_totp")
        send_response(sock, False, error="credenciais invalidas")
        return
    token = secrets.token_hex(SESSION_TOKEN_SIZE)
    with state.lock:
        state.sessions[token] = {"username": username}
    log_event(LOG_PATH, "login_ok", user=username, peer=peer[0])
    send_response(sock, True, {"session_token": token, "username": username})


def _session_user(state: ServerState, token: str) -> str:
    sess = state.sessions.get(token)
    if not sess:
        raise RuntimeError("sessao invalida")
    return sess["username"]


def handle_addblock(state: ServerState, sock, conn_id, data, peer):
    username = _session_user(state, data["session_token"])
    iv = b64d(data["iv"])
    payload = b64d(data["payload"])
    with state.lock:
        validate_chain(state.chain)  # pré-condição
        prev = state.chain[-1]
        block = make_block(
            index=prev.index + 1,
            owner=username,
            iv=iv,
            payload=payload,
            prev_hash=prev.hash,
        )
        state.chain.append(block)
        try:
            validate_chain(state.chain)
        except ChainError:
            state.chain.pop()
            raise
        state.save_chain()
    log_event(LOG_PATH, "addblock_ok", user=username, peer=peer[0], index=block.index)
    send_response(sock, True, {"index": block.index, "hash": b64e(block.hash)})


def handle_list(state: ServerState, sock, conn_id, data, peer):
    username = _session_user(state, data["session_token"])
    with state.lock:
        try:
            validate_chain(state.chain)
            chain_ok = True
            chain_err = None
        except ChainError as exc:
            chain_ok = False
            chain_err = str(exc)
            log_event(LOG_PATH, "chain_invalid", user=username, peer=peer[0], reason=chain_err)
        blocks = [b.to_dict() for b in state.chain]
    send_response(sock, True, {"blocks": blocks, "chain_ok": chain_ok, "chain_error": chain_err})


def handle_tamper(state: ServerState, sock, conn_id, data, peer):
    """Comando de DEMONSTRAÇÃO: adultera um bloco da cadeia para provar detecção.

    Aceita `mode` ∈ {ciphertext, prev_hash} e `index` ≥ 1. Requer sessão ativa (qualquer usuário).
    """
    _session_user(state, data["session_token"])
    mode = data["mode"]
    index = int(data["index"])
    with state.lock:
        if index <= 0 or index >= len(state.chain):
            send_response(sock, False, error="indice fora do intervalo (use >=1)")
            return
        target = state.chain[index]
        if mode == "ciphertext":
            flipped = bytearray(target.payload)
            flipped[0] ^= 0x01
            state.chain[index] = Block(
                index=target.index,
                timestamp=target.timestamp,
                owner=target.owner,
                iv=target.iv,
                payload=bytes(flipped),
                prev_hash=target.prev_hash,
                hash=target.hash,  # hash antigo para simular adulteração silenciosa
            )
        elif mode == "prev_hash":
            bad = bytearray(target.prev_hash)
            bad[0] ^= 0x01
            state.chain[index] = Block(
                index=target.index,
                timestamp=target.timestamp,
                owner=target.owner,
                iv=target.iv,
                payload=target.payload,
                prev_hash=bytes(bad),
                hash=target.hash,
            )
        else:
            send_response(sock, False, error="mode invalido (ciphertext|prev_hash)")
            return
        state.save_chain()
    log_event(LOG_PATH, "tamper_demo", peer=peer[0], index=index, mode=mode)
    send_response(sock, True, {"index": index, "mode": mode})


def handle_logout(state: ServerState, sock, conn_id, data, peer):
    token = data.get("session_token")
    with state.lock:
        sess = state.sessions.pop(token, None)
    if sess:
        log_event(LOG_PATH, "logout", user=sess["username"], peer=peer[0])
    send_response(sock, True, {})


def handle_logs(state: ServerState, sock, conn_id, data, peer):
    _session_user(state, data["session_token"])
    tail = int(data.get("tail", 50))
    if LOG_PATH.exists():
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()[-tail:]
    else:
        lines = []
    send_response(sock, True, {"lines": lines})


DISPATCH = {
    "REGISTER": handle_register,
    "HELLO": handle_hello,
    "AUTH": handle_auth,
    "ADDBLOCK": handle_addblock,
    "LIST": handle_list,
    "TAMPER": handle_tamper,
    "LOGOUT": handle_logout,
    "LOGS": handle_logs,
}


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(state: ServerState, host: str, port: int) -> ThreadedServer:
    handler_cls = type("BoundHandler", (Handler,), {"state": state})
    return ThreadedServer((host, port), handler_cls)


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor da mini-blockchain")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument(
        "--master-password",
        help="Senha mestre do servidor (se omitido, pergunta interativamente). Apenas para testes automatizados.",
    )
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    salt = load_or_create_master_salt(SALT_PATH)
    master_pw = args.master_password if args.master_password is not None else getpass.getpass("senha mestre do servidor: ")
    if not master_pw:
        raise SystemExit("senha mestre obrigatoria")
    master_key = derive_master_key(master_pw, salt)

    try:
        state = ServerState(master_key)
    except StorageError as exc:
        raise SystemExit(str(exc)) from exc

    log_event(LOG_PATH, "server_start", host=args.host, port=args.port)
    with make_server(state, args.host, args.port) as srv:
        print(f"[servidor] escutando em {args.host}:{args.port}  (Ctrl+C para encerrar)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[servidor] encerrando")
            log_event(LOG_PATH, "server_stop")


if __name__ == "__main__":
    main()
