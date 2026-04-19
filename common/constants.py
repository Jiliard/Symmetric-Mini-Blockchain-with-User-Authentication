"""Parâmetros criptográficos e de protocolo compartilhados entre cliente e servidor.

Nenhuma chave ou IV é definido aqui - apenas tamanhos, contagens de iteração e rótulos.
"""

HOST = "127.0.0.1"
PORT = 9099

PBKDF2_ITERATIONS = 300_000
PBKDF2_HASH = "sha256"

SALT_SIZE = 16
AES_KEY_SIZE = 32
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16

SESSION_TOKEN_SIZE = 32
CHALLENGE_NONCE_SIZE = 32

TOTP_SECRET_BYTES = 20
TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1

MAX_MESSAGE_BYTES = 8 * 1024 * 1024

LOGIN_CONTEXT = b"MINI-BC|LOGIN"
BLOCK_AAD_PREFIX = b"MINI-BC|BLOCK"
