from __future__ import annotations
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

_lock = Lock()

def log_event(path: Path, event: str, **fields) -> None:
    parts = [datetime.now(UTC).isoformat(), event]
    for k, v in fields.items():
        parts.append(f"{k}={v}")
    line = " | ".join(parts) + "\n"
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
