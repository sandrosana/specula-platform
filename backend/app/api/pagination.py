"""Opaque cursors for keyset pagination (docs/architettura.md §9)."""

import base64
import json
from typing import Any

from fastapi import HTTPException


def encode_cursor(position: dict[str, Any]) -> str:
    raw = json.dumps(position, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> dict[str, Any]:
    """Decode a cursor produced by encode_cursor; 400 if it was tampered with."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Invalid cursor.")
    return value
