from __future__ import annotations
import base64
import hmac
import pyotp
from common.constants import LOGIN_CONTEXT, TOTP_DIGITS, TOTP_INTERVAL, TOTP_WINDOW

def verify_challenge(auth_key: bytes, nonce: bytes, response: bytes) -> bool:
    expected = hmac.new(auth_key, nonce + LOGIN_CONTEXT, "sha256").digest()
    return hmac.compare_digest(expected, response)

def verify_totp(secret_bytes: bytes, code: str) -> bool:
    secret_b32 = base64.b32encode(secret_bytes).decode("ascii").rstrip("=")
    totp = pyotp.TOTP(secret_b32, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    return totp.verify(code, valid_window=TOTP_WINDOW)
