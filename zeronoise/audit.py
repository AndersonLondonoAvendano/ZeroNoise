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
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_LOG_PATH = Path(__file__).parent.parent / "audit.log"

# Keys whose values are replaced with '***REDACTED***' before writing to audit.log
_SENSITIVE_KEYS = frozenset({
    "api_key", "dt_api_key", "anthropic_api_key",
    "token", "password", "secret",
})


def _mask_sensitive(data: dict) -> dict:
    """Replace values of sensitive keys with '***REDACTED***'."""
    return {
        k: "***REDACTED***" if k.lower() in _SENSITIVE_KEYS else v
        for k, v in data.items()
    }


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


def _log_internal_error(tool_name: str, tb: str) -> None:
    """Write an internal error traceback to audit.log without exposing it to callers."""
    _write_entry({
        "tool_name": tool_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "internal_error",
        "traceback": tb[:2000],
    })


def audit_tool(side_effects: str = "none"):
    """
    Decorator that logs tool execution to audit.log.

    Sensitive parameter values are masked before writing.

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
                masked_input = _mask_sensitive(
                    {k: str(v)[:200] for k, v in kwargs.items()}
                )
                _write_entry({
                    "tool_name": fn.__name__,
                    "timestamp": timestamp,
                    "input": masked_input,
                    "duration_ms": duration_ms,
                    "output_hash": _hash_output(result) if result is not None else None,
                    "side_effects": side_effects,
                    "error": error,
                })
        return wrapper
    return decorator


def safe_tool(func: Callable):
    """
    Decorator: catches unhandled exceptions and returns a structured error dict.

    Apply AFTER @audit_tool so the audit entry is always recorded even on error:

        @safe_tool
        @audit_tool(side_effects="none")
        async def my_tool(...): ...

    - ValueError / TypeError  → returned as "validation_error" (no internal traceback exposed).
    - Any other exception     → traceback written to audit.log, generic message returned to caller.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except (ValueError, TypeError) as e:
            return {"error": "validation_error", "message": str(e), "tool": func.__name__}
        except Exception:
            tb = traceback.format_exc()
            _log_internal_error(func.__name__, tb)
            return {
                "error": "internal_error",
                "message": (
                    f"Error interno en '{func.__name__}'. "
                    "Revisar audit.log para detalles."
                ),
                "tool": func.__name__,
            }
    return wrapper
