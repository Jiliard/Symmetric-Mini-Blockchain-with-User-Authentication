# Mini-Blockchain Simétrica Multiusuário

Implementação em Python de uma mini-blockchain multiusuário com:

- **Confidencialidade** por AES-GCM (cifragem autenticada por bloco, IV único)
- **Autenticação forte** senha + TOTP (RFC 6238)
- **Integridade da cadeia** por SHA-256 encadeado (cada bloco referencia o hash do anterior)
- **Isolamento multiusuário**: cada usuário só decifra seus próprios blocos
- **Separação cliente/servidor** via socket TCP: o servidor *nunca* recebe a senha, a `enc_key`
  ou o plaintext dos blocos do usuário
- **Persistência cifrada** em `data/users.enc` e `data/blockchain.enc` com chave mestre do operador
- **Log de auditoria** em `data/access.log`
- **Validação automática da cadeia** a cada novo bloco e a cada leitura

---

## 1. Tutorial de execução

Pré-requisito: Python **≥ 3.10** (o código usa `X | None`, `datetime.UTC` etc.). Em macOS:
`brew install python@3.13` (ou `3.11`).

```bash
cd trabalho-blockchain
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# roda os testes unitários + ponta-a-ponta (servidor sobe em thread)
pytest -q tests/

# roda a aplicação em dois terminais -----------------------------------------
# terminal 1 (servidor):
python -m server.main          # vai pedir uma "senha mestre do servidor"
# terminal 2 (cliente):
python -m client.main          # menu textual
#  ou (GUI):
python -m client.gui           # janela Tkinter

# script de demonstração ponta-a-ponta (limpa data/, sobe servidor, exerce
# todos os casos de teste exigidos e imprime access.log):
bash demo.sh
```

> Em macOS, o Python do Homebrew não traz Tkinter por padrão. Se `python -m client.gui`
> reclamar de `_tkinter`, instale com `brew install python-tk@3.13` (ou a versão
> correspondente ao seu Python).

No primeiro login/registro o cliente exibe o **segredo TOTP** em base32 e uma URI
`otpauth://`. Para obter o código a qualquer momento sem precisar do Google Authenticator:

```bash
python -m client.totp_helper 4GHPLOA45RFWBKDRVIFZVBOFVSMYNSL3
```

### Menu

```
1) Cadastrar novo usuario
2) Login
3) Adicionar bloco (requer login)
4) Listar / validar cadeia
5) Ler meus blocos (decifra apenas os meus)
6) Adulterar bloco (teste de integridade)
7) Mostrar log de acesso (requer login)
8) Logout
0) Sair
```

---

## 2. Estrutura

```
trabalho-blockchain/
├── common/        # framing de protocolo + constantes
├── client/        # crypto do usuário, sessão TCP, menu CLI, GUI Tk, totp_helper
├── server/        # master key, storage cifrado, blockchain, auth, dispatcher TCP, audit
├── tests/         # pytest + demo_script.py
├── data/          # criada no primeiro run do servidor
├── demo.sh        # roteiro ponta-a-ponta
└── requirements.txt
```

---

## 3. Documentação do modelo criptográfico

### 3.1 Derivação de chave simétrica (PBKDF2)

- Algoritmo: **PBKDF2-HMAC-SHA256**, **300 000 iterações**, **salt aleatório de 16 bytes**
  por usuário (`client/crypto.py::derive_user_keys`; constantes em `common/constants.py`).
- Cada usuário gera um `salt_kdf` no cadastro e o servidor o armazena (dentro do arquivo
  cifrado). Uma única invocação do KDF produz **64 bytes**, divididos em:
  - `auth_key` (32 bytes): prova de conhecimento de senha no desafio-resposta.
  - `enc_key`  (32 bytes): cifra o payload dos blocos do usuário. **Fica apenas na memória
    do cliente** — nunca é escrita em disco, nunca trafega na rede, nunca é usada em
    variáveis globais/ambiente (requisito 6.i).
- Chave mestre do servidor: PBKDF2 da senha do operador + `data/master.salt`
  (`server/master_key.py`). Usada só para cifrar `users.enc` e `blockchain.enc`; nunca toca
  dados do usuário.

**Caso de teste 1** (`tests/test_crypto.py`): mesma senha + mesmo salt ⇒ mesma chave;
salts diferentes ⇒ chaves diferentes; senhas diferentes ⇒ chaves diferentes.

### 3.2 TOTP (RFC 6238)

- Segredo de **20 bytes** aleatórios, gerado no cliente no cadastro, codificado em **base32**
  para exibição e para o link `otpauth://totp/...`. O cliente envia o segredo ao servidor uma
  única vez durante o registro; o servidor o armazena cifrado em `users.enc`.
- Intervalo de **30 s**, **6 dígitos**, janela de tolerância = 1 (±30 s) na verificação
  (`server/auth.py::verify_totp`, parâmetros em `common/constants.py`).
- Cálculo feito pela biblioteca `pyotp` (HMAC-SHA1 padronizado). O utilitário
  `client/totp_helper.py` permite ao usuário gerar o código localmente com o mesmo segredo
  cadastrado — simulando o app do celular.

**Casos de teste 1 e 2 (autenticação)** em `tests/test_e2e.py::test_login_totp_errado` e
`test_login_senha_errada`.

### 3.3 Login via desafio-resposta (a senha nunca sai do cliente)

1. Cliente envia `HELLO {username}` → servidor responde `{salt_kdf, nonce_32B}`.
2. Cliente deriva `auth_key` da senha digitada e calcula
   `response = HMAC-SHA256(auth_key, nonce || "MINI-BC|LOGIN")`.
3. Cliente envia `AUTH {response, totp_code}`; servidor verifica com `hmac.compare_digest`
   + `pyotp.TOTP(...).verify(code, valid_window=1)`.
4. Se válido, servidor emite um `session_token` aleatório de 32 bytes que autoriza as
   operações subsequentes.

O servidor responde com um salt falso quando o usuário não existe, evitando vazar a
existência de contas (`server/main.py::handle_hello`).

### 3.4 Criptografia por bloco (AES-GCM) e AAD

- Cada bloco carrega um **IV de 12 bytes** gerado aleatoriamente no cliente
  (`client/crypto.py::encrypt_block`). IVs nunca são reutilizados porque são sorteados por
  `os.urandom(12)` a cada chamada.
- AAD (Additional Authenticated Data) = `"MINI-BC|BLOCK|<owner>|<index>"`. Isso impede que
  um atacante "mova" um bloco de dono ou reordene blocos sem invalidar a tag GCM.
- A tag GCM de 16 bytes fica concatenada no fim do `payload`. O servidor trata `iv` e
  `payload` como bytes opacos — ele não tem `enc_key` e, portanto, não consegue decifrar.

**Caso de teste 4 (multiusuário)** em `tests/test_e2e.py::test_tamper_ciphertext_detectado`
confirma que qualquer alteração no `payload` resulta em `InvalidTag` no cliente.

### 3.5 Encadeamento da blockchain

Cada bloco guarda:

| Campo       | Conteúdo                                                                  |
|-------------|---------------------------------------------------------------------------|
| `index`     | posição na cadeia (0 = genesis)                                           |
| `timestamp` | ISO-8601 UTC                                                              |
| `owner`     | username que criou o bloco                                                |
| `iv`        | 12 bytes (AES-GCM)                                                        |
| `payload`   | ciphertext + tag GCM                                                      |
| `prev_hash` | SHA-256 do bloco anterior                                                 |
| `hash`      | SHA-256 de `index ‖ ts ‖ owner ‖ iv ‖ payload ‖ prev_hash` do próprio bloco |

A função `validate_chain` (`server/blockchain.py`) é chamada:

1. No start-up, ao abrir `blockchain.enc`;
2. **Antes** e **depois** de cada `ADDBLOCK`;
3. Em cada `LIST`.

Qualquer divergência de `prev_hash` ou recomputação de `hash` interrompe a validação e é
reportada em `chain_ok=False` + `chain_error=...` + log de `chain_invalid`.

**Caso de teste 5 (multiusuário)** em `tests/test_e2e.py::test_tamper_prev_hash_detectado`.

---

## 4. Conformidade com o item 6 do enunciado

| Requisito | Como atendemos |
|-----------|----------------|
| **6.i** chave/IV não em variáveis globais/ambiente, cliente e servidor como máquinas diferentes | `enc_key` só existe como atributo de uma instância `SessionInfo` no processo cliente; servidor nunca a recebe. Toda comunicação passa por TCP (`socketserver.ThreadingTCPServer`). |
| **6.ii** PBKDF2/Scrypt para gerar chaves | `client/crypto.py` e `server/master_key.py` usam `PBKDF2HMAC` com 300 000 iterações. |
| **6.iii** criptografia autenticada | `AESGCM` (do `cryptography.hazmat.primitives.ciphers.aead`) em todos os blocos **e** nos arquivos persistidos. |
| **6.iv** decisões próprias sobre formatos | Protocolo JSON length-prefixed; blocos com AAD `"MINI-BC|BLOCK|<owner>|<index>"`; arquivos `[iv ‖ ct+tag]`. |
| **6.v** nenhuma chave/IV hardcoded | Toda chave vem de `PBKDF2` sobre senha + salt; todos os IVs vêm de `os.urandom`. A busca `grep -R "\\x00"` no repositório só encontra o `prev_hash` do bloco genesis (bytes públicos, não secretos). |
| **6.vi** parâmetros guardados em arquivo cifrado; apenas salt em claro | `data/master.salt` é o único arquivo em claro. `users.enc` e `blockchain.enc` são AES-GCM com a chave mestre derivada da senha do operador. |

---

## 5. Casos de teste cobertos

### Autenticação (`tests/test_e2e.py`)
1. Login correto + TOTP válido → sucesso (`test_registro_login_add_list`).
2. TOTP inválido → falha (`test_login_totp_errado`).
3. Senha incorreta → falha (`test_login_senha_errada`).

### Blockchain multiusuário (`tests/test_e2e.py`, `tests/test_chain.py`)
1. Alice adiciona bloco → cifrado corretamente.
2. Bob adiciona bloco → cifrado corretamente.
3. Alice lê sua blockchain → decifra os próprios, não decifra os de Bob
   (`test_multiusuario_isolamento`).
4. Adulteração de `ciphertext` → `InvalidTag` (`test_tamper_ciphertext_detectado`).
5. Adulteração de `prev_hash` → erro de validação (`test_tamper_prev_hash_detectado`).

### KDF (`tests/test_crypto.py`)
1. Mesma senha + mesmo salt → mesma chave (`test_kdf_determinismo`).
2. Salt diferente → chave diferente (`test_kdf_salt_diferente_chave_diferente`).

Todos os testes: `pytest -q tests/` (17 passam).

---

## 6. Mapa de requisitos → código

Para a apresentação, cada item do enunciado pode ser aberto no arquivo indicado.

### 2.1 Cadastro e login

| Requisito | Arquivo:símbolo |
|-----------|-----------------|
| Cadastro com username/senha | `client/session.py::Client.register` |
| Senha derivada via PBKDF2 | `client/crypto.py::derive_user_keys` (300 000 iter., SHA-256) |
| Armazenamento da chave TOTP | `server/main.py::handle_register` grava em `data/users.enc` (cifrado) |
| Login exige senha correta + TOTP válido | `server/main.py::handle_auth` → `server/auth.py::verify_challenge` e `verify_totp` |
| **Chave de sessão segura para cifrar blocos** | `client/session.py::SessionInfo.session_key` — derivada no login, guardada apenas em memória, descartada no logout |

### 2.2 Registro de blocos

| Requisito | Arquivo:símbolo |
|-----------|-----------------|
| Usuário autenticado cria bloco com dados arbitrários | `client/session.py::Client.add_block` |
| Dados cifrados com AES-GCM usando a chave de sessão | `client/crypto.py::encrypt_block` |
| IV único por bloco | `os.urandom(12)` em `encrypt_block` |
| `timestamp` | `server/blockchain.py::make_block` (ISO-8601 UTC) |
| `hash_prev` | `server/main.py::handle_addblock` usa `state.chain[-1].hash` |
| `owner` | Servidor lê o username a partir do `session_token`, não confia no cliente |

### 2.3 Leitura da blockchain

| Requisito | Arquivo:símbolo |
|-----------|-----------------|
| Listar todos os blocos | `client/session.py::Client.list_chain` / `handle_list` |
| Decifrar só os próprios | `client/session.py::Client.decrypt_mine` (filtra por `owner == self.session.username`) |
| Integridade de `hash_prev` | `server/blockchain.py::validate_chain` |
| Validade do AES-GCM | `client/crypto.py::decrypt_block` (qualquer alteração → `InvalidTag`) |

### 2.4 / 6 — Segurança

| Requisito | Onde | Observação |
|-----------|------|------------|
| 2.4 AES-GCM confidencial+íntegro | todos os blocos e ambos os arquivos persistidos | autenticada |
| 2.4 IV único | `os.urandom(12)` por bloco | nunca fixo |
| 2.4 PBKDF2 | `client/crypto.py`, `server/master_key.py` | 300 000 iter. |
| 2.4 TOTP obrigatório | `handle_auth` exige TOTP no login (que habilita qualquer `ADDBLOCK` subsequente da sessão) | interpretação: 2FA no login; `session_token` autoriza as operações |
| 2.4 detecção de alterações | `validate_chain` + `InvalidTag` no cliente + `access.log` | evento `chain_invalid` registrado |
| 6.i cliente e servidor "em máquinas diferentes" | processos separados via TCP; `enc_key` jamais sai do cliente | `SessionInfo.enc_key` é atributo de instância, não global |
| 6.ii PBKDF2/Scrypt para chaves | `PBKDF2HMAC` | IVs por `os.urandom` (aleatório é a recomendação para GCM) |
| 6.iii criptografia autenticada | `AESGCM` em blocos e em arquivos | GCM tag de 16 B |
| 6.iv decisões de formato | AAD `MINI-BC\|BLOCK\|<owner>\|<index>`, framing length-prefixed | `common/protocol.py`, `client/crypto.py` |
| 6.v nenhum hardcode | — | todas as chaves/IVs vêm de KDF ou `os.urandom` |
| 6.vi parâmetros em arquivo cifrado; só salt em claro | `data/master.salt` em claro; `users.enc` e `blockchain.enc` AES-GCM | `server/storage.py` |

### Casos de teste explícitos

| Caso | Onde está |
|------|-----------|
| Login correto + TOTP válido → sucesso | `tests/test_e2e.py::test_registro_login_add_list` |
| Login com TOTP inválido → falha | `tests/test_e2e.py::test_login_totp_errado` |
| Login com senha incorreta → falha | `tests/test_e2e.py::test_login_senha_errada` |
| A adiciona + B adiciona, A lê só os próprios | `tests/test_e2e.py::test_multiusuario_isolamento` |
| Tamper ciphertext → falha de integridade | `tests/test_e2e.py::test_tamper_ciphertext_detectado` |
| Tamper `hash_prev` → erro de validação | `tests/test_e2e.py::test_tamper_prev_hash_detectado` |
| Mesma senha + salt → mesma chave | `tests/test_crypto.py::test_kdf_determinismo` |
| Salt diferente → chave diferente | `tests/test_crypto.py::test_kdf_salt_diferente_chave_diferente` |

---

## 7. Comandos úteis

```bash
# validar cadeia manualmente depois de adulteração do arquivo
python -c "import json; from pathlib import Path; from server.storage import load_json; \
from server.blockchain import Block, validate_chain; \
from server.master_key import derive_master_key, load_or_create_master_salt; \
key=derive_master_key(input('senha mestre: '), load_or_create_master_salt(Path('data/master.salt'))); \
blocks=[Block.from_dict(b) for b in load_json(key, Path('data/blockchain.enc'), [])]; \
validate_chain(blocks); print('ok', len(blocks))"

# mostrar o access.log
cat data/access.log
```
