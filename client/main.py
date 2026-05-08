from __future__ import annotations
import argparse
import getpass
import sys
from client.session import Client, ClientError
from common.constants import HOST, PORT

def _read(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\n")

def _read_password(prompt: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return _read(prompt)

def do_register(client: Client) -> None:
    username = _read("novo username: ").strip()
    pw1 = _read_password("senha: ")
    pw2 = _read_password("confirme a senha: ")
    if pw1 != pw2:
        print("senhas nao conferem")
        return
    secret, uri = client.register(username, pw1)
    print(f"usuario '{username}' cadastrado.")
    print(f"SEGREDO TOTP (base32): {secret}")
    print(f"otpauth URI: {uri}")
    print("Guarde o segredo — use-o no Google Authenticator ou em `python -m client.totp_helper <segredo>`.")

def do_login(client: Client) -> None:
    username = _read("username: ").strip()
    password = _read_password("senha: ")
    code = _read("codigo TOTP: ").strip()
    sess = client.login(username, password, code)
    print(f"login ok: {sess.username}")

def do_add(client: Client) -> None:
    data = _read("dados do bloco: ")
    reply = client.add_block(data.encode("utf-8"))
    print(f"bloco #{reply['index']} adicionado.")

def do_list(client: Client) -> None:
    reply = client.list_chain()
    blocks = reply["blocks"]
    print(f"cadeia com {len(blocks)} bloco(s)  chain_ok={reply['chain_ok']}")
    if reply.get("chain_error"):
        print(f"!! CADEIA INVALIDA: {reply['chain_error']}")
    for b in blocks:
        print(f"  [{b['index']}] owner={b['owner']} ts={b['timestamp']} hash={b['hash'][:16]}...")

def do_read_mine(client: Client) -> None:
    reply = client.list_chain()
    if not reply["chain_ok"]:
        print(f"!! cadeia comprometida: {reply['chain_error']}")
    decoded = client.decrypt_mine(reply["blocks"])
    for entry in decoded:
        if entry.get("plaintext") is not None:
            print(f"  [{entry['index']}] ({entry['owner']}) -> {entry['plaintext']}")
        elif "error" in entry:
            print(f"  [{entry['index']}] ({entry['owner']}) !! {entry['error']}")
        else:
            print(f"  [{entry['index']}] ({entry['owner']}) -- {entry.get('note', 'nao decifravel')}")

def do_tamper(client: Client) -> None:
    idx_s = _read("indice do bloco (>=1): ").strip()
    mode = _read("modo (ciphertext|prev_hash): ").strip()
    reply = client.tamper(int(idx_s), mode)
    print(f"adulterado: indice={reply['index']} modo={reply['mode']}")

def do_logs(client: Client) -> None:
    for line in client.logs(100):
        print(line)

ACTIONS = {
    "1": do_register,
    "2": do_login,
    "3": do_add,
    "4": do_list,
    "5": do_read_mine,
    "6": do_tamper,
    "7": do_logs,
}

def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente da mini-blockchain")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    client = Client(args.host, args.port)
    client.connect()
    print(f"[cliente] conectado em {args.host}:{args.port}")
    try:
        while True:
            print(MENU)
            try:
                choice = _read("> ").strip()
            except EOFError:
                break
            if choice == "0":
                break
            if choice == "8":
                client.logout()
                print("logout ok")
                continue
            action = ACTIONS.get(choice)
            if not action:
                print("opcao invalida")
                continue
            try:
                action(client)
            except ClientError as exc:
                print(f"erro: {exc}")
            except EOFError:
                break
    finally:
        client.logout()
        client.close()

if __name__ == "__main__":
    main()
