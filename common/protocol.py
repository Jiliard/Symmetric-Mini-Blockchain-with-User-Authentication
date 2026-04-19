"""Framing length-prefixed JSON para TCP + helpers para serializar bytes."""

import base64
import json
import socket
import struct

from common.constants import MAX_MESSAGE_BYTES


class ProtocolError(Exception):
    pass


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def send_message(sock: socket.socket, op: str, data: dict) -> None:
    payload = json.dumps({"op": op, "data": data}, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError("mensagem excede tamanho maximo")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def send_response(sock: socket.socket, ok: bool, payload: dict | None = None, error: str | None = None) -> None:
    body: dict = {"ok": ok}
    if payload is not None:
        body["data"] = payload
    if error is not None:
        body["error"] = error
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        part = sock.recv(n - len(chunks))
        if not part:
            raise ProtocolError("conexao encerrada")
        chunks.extend(part)
    return bytes(chunks)


def recv_message(sock: socket.socket) -> tuple[str, dict]:
    header = _recv_exactly(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_MESSAGE_BYTES:
        raise ProtocolError("mensagem recebida excede tamanho maximo")
    body = _recv_exactly(sock, length)
    try:
        msg = json.loads(body.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"json invalido: {exc}") from exc
    if "op" not in msg:
        raise ProtocolError("mensagem sem campo 'op'")
    return msg["op"], msg.get("data", {})


def recv_response(sock: socket.socket) -> tuple[bool, dict, str | None]:
    header = _recv_exactly(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_MESSAGE_BYTES:
        raise ProtocolError("resposta excede tamanho maximo")
    body = _recv_exactly(sock, length)
    msg = json.loads(body.decode("utf-8"))
    return msg.get("ok", False), msg.get("data", {}), msg.get("error")
