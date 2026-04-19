"""Roteiro que cobre os casos exigidos pelo enunciado (executado por demo.sh).

Cobertura:
- Registro de Alice e Bob.
- Login correto + TOTP válido  -> sucesso.
- Login com TOTP inválido       -> falha.
- Login com senha incorreta     -> falha.
- Alice e Bob adicionam blocos  -> criptografados corretamente.
- Alice lê a cadeia             -> decifra seus blocos, marca os de Bob como opacos.
- Adulteração de ciphertext     -> cliente detecta falha de integridade.
- Adulteração de prev_hash      -> cadeia reportada como inválida.
"""

from __future__ import annotations

import pyotp

from client.session import Client, ClientError
from common.constants import HOST, PORT


def _totp(secret_b32: str) -> str:
    return pyotp.TOTP(secret_b32).now()


def section(title: str) -> None:
    print("\n===", title, "===")


def main() -> None:
    section("Registro")
    with _connect() as c:
        alice_secret, alice_uri = c.register("alice", "pw-alice-1")
        bob_secret, bob_uri = c.register("bob", "pw-bob-2")
        print(f"alice  segredo={alice_secret}")
        print(f"alice  uri={alice_uri}")
        print(f"bob    segredo={bob_secret}")

    section("Autenticação: senha/TOTP errados")
    with _connect() as c:
        try:
            c.login("alice", "senha-errada", _totp(alice_secret))
        except ClientError as exc:
            print(f"login senha errada: falha esperada -> {exc}")
        try:
            c.login("alice", "pw-alice-1", "000000")
        except ClientError as exc:
            print(f"login totp errado: falha esperada -> {exc}")

    section("Alice adiciona blocos")
    with _connect() as c:
        c.login("alice", "pw-alice-1", _totp(alice_secret))
        print("bloco 1 ->", c.add_block(b"transacao de alice #1"))
        print("bloco 2 ->", c.add_block(b"transacao de alice #2"))

    section("Bob adiciona bloco")
    with _connect() as c:
        c.login("bob", "pw-bob-2", _totp(bob_secret))
        print("bloco 3 ->", c.add_block(b"transacao de bob #1"))

    section("Alice lê e decifra apenas os próprios blocos")
    with _connect() as c:
        c.login("alice", "pw-alice-1", _totp(alice_secret))
        reply = c.list_chain()
        print(f"chain_ok={reply['chain_ok']}  total={len(reply['blocks'])}")
        for e in c.decrypt_mine(reply["blocks"]):
            if e.get("plaintext") is not None:
                print(f"  [{e['index']}] ({e['owner']}) plaintext: {e['plaintext']!r}")
            elif "error" in e:
                print(f"  [{e['index']}] ({e['owner']}) ERRO: {e['error']}")
            else:
                print(f"  [{e['index']}] ({e['owner']}) opaco ({e.get('note', '')})")

    section("Adulteração de ciphertext no bloco 1 (demo)")
    with _connect() as c:
        c.login("alice", "pw-alice-1", _totp(alice_secret))
        c.tamper(1, "ciphertext")
        reply = c.list_chain()
        print(f"chain_ok={reply['chain_ok']}  error={reply.get('chain_error')}")
        for e in c.decrypt_mine(reply["blocks"]):
            if "error" in e:
                print(f"  [{e['index']}] ({e['owner']}) DETECTADO: {e['error']}")

    section("Adulteração de prev_hash no bloco 2 (demo)")
    with _connect() as c:
        c.login("alice", "pw-alice-1", _totp(alice_secret))
        c.tamper(2, "prev_hash")
        reply = c.list_chain()
        print(f"chain_ok={reply['chain_ok']}  error={reply.get('chain_error')}")


def _connect() -> Client:
    c = Client(HOST, PORT)
    c.connect()
    return c


if __name__ == "__main__":
    main()
