"""
Tool execution audit logger.

Every MCP tool invocation writes a JSON-Lines entry to audit.log so that
security teams can reconstruct what the system did, when, and why.

Logged fields (Section 12 of the MCP Server Specification):
  tool_name, timestamp, input_summary, duration_ms, side_effects
"""

import functools
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_LOG_PATH = Path(__file__).parent.parent / "audit.log"


def _write_entry(entry: dict) -> None:
    try:
        with _LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass  # audit failure must never break the tool


def _hash_output(result: Any) -> str:
    try:
        raw = json.dumps(result, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    except Exception:
        return "unhashable"


def audit_tool(side_effects: str = "none"):
    """
    Decorator that logs tool execution to audit.log.

    Args:
        side_effects: one of "none" | "external_write" | "file_write"
    """
    def decorator(fn: Callable):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            start = time.monotonic()
            timestamp = datetime.now(timezone.utc).isoformat()
            result = None
            error = None
            try:
                result = await fn(*args, **kwargs)
                return result
            except Exception as exc:
                error = str(exc)
                raise
            finally:
                duration_ms = round((time.monotonic() - start) * 1000, 1)
                _write_entry({
                    "tool_name": fn.__name__,
                    "timestamp": timestamp,
                    "input": {k: str(v)[:200] for k, v in kwargs.items()},
                    "duration_ms": duration_ms,
                    "output_hash": _hash_output(result) if result is not None else None,
                    "side_effects": side_effects,
                    "error": error,
                })
        return wrapper
    return decorator
