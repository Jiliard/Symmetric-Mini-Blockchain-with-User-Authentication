#!/usr/bin/env bash
# Roteiro ponta-a-ponta: sobe o servidor, registra 2 usuários, adiciona blocos,
# lê por cada usuário, adultera um bloco e valida. Limpa data/ antes de rodar.

set -euo pipefail

cd "$(dirname "$0")"
source .venv/bin/activate

DATA_DIR="./data"
rm -rf "$DATA_DIR"

MASTER_PW="senha-mestre-demo"

echo "[demo] iniciando servidor em background…"
python -m server.main --master-password "$MASTER_PW" >/tmp/mini-bc-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Espera o socket abrir.
for _ in $(seq 1 30); do
  if python -c "import socket; s=socket.socket(); s.settimeout(0.2); s.connect(('127.0.0.1', 9099))" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

echo "[demo] rodando script de demonstração…"
python -m tests.demo_script
echo "[demo] fim. Log do servidor:"
tail -n 40 /tmp/mini-bc-server.log
echo "[demo] access.log:"
cat "$DATA_DIR/access.log"
