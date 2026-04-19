"""Utilitário para gerar o código TOTP a partir do segredo (simulando o app do celular).

Uso:  python -m client.totp_helper <segredo_base32>
"""

from __future__ import annotations

import sys

import pyotp

from common.constants import TOTP_DIGITS, TOTP_INTERVAL


def main() -> None:
    if len(sys.argv) != 2:
        print("uso: python -m client.totp_helper <segredo_base32>", file=sys.stderr)
        sys.exit(2)
    secret = sys.argv[1].strip().replace(" ", "")
    try:
        code = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).now()
    except Exception as exc:  # noqa: BLE001
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)
    print(code)


if __name__ == "__main__":
    main()
