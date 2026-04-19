import base64
import secrets

import pyotp

from server.auth import verify_totp


def test_totp_valido():
    secret_bytes = secrets.token_bytes(20)
    secret_b32 = base64.b32encode(secret_bytes).decode().rstrip("=")
    code = pyotp.TOTP(secret_b32).now()
    assert verify_totp(secret_bytes, code)


def test_totp_invalido_rejeitado():
    secret_bytes = secrets.token_bytes(20)
    assert not verify_totp(secret_bytes, "000000")
