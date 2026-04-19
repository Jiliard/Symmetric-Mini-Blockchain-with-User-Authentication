"""Sobe um servidor TCP em thread com data/ temporário para testes end-to-end."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import pytest

from common.constants import HOST


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path, monkeypatch):
    from server import main as server_main
    from server.master_key import derive_master_key, load_or_create_master_salt

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(server_main, "DATA_DIR", data_dir)
    monkeypatch.setattr(server_main, "USERS_PATH", data_dir / "users.enc")
    monkeypatch.setattr(server_main, "CHAIN_PATH", data_dir / "blockchain.enc")
    monkeypatch.setattr(server_main, "SALT_PATH", data_dir / "master.salt")
    monkeypatch.setattr(server_main, "LOG_PATH", data_dir / "access.log")
    from server import audit as _audit  # noqa: F401
    # audit.log_event usa o caminho passado - LOG_PATH é importado pelo main só.

    salt = load_or_create_master_salt(data_dir / "master.salt")
    key = derive_master_key("senha-mestre-teste", salt)
    state = server_main.ServerState(key)

    port = _free_port()
    srv = server_main.make_server(state, HOST, port)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"host": HOST, "port": port, "data_dir": Path(data_dir), "state": state}
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)
