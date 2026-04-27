import os
import stat
import sys
from pathlib import Path

from zeronoise.config import settings
from zeronoise.server import mcp


def _startup_security_checks(cfg) -> None:
    """Security checks at startup. Warns on stderr for insecure configurations."""

    # 1. Warn if SSE transport is bound to all interfaces without authentication
    if cfg.mcp_transport == "sse":
        host = getattr(cfg, "mcp_host", "127.0.0.1")
        if host == "0.0.0.0":
            print(
                "[SECURITY WARNING] MCP_TRANSPORT=sse expuesto en 0.0.0.0. "
                "Configurar MCP_HOST=127.0.0.1 para producción.",
                file=sys.stderr,
            )

    # 2. Ensure audit.log exists and has restrictive permissions
    log_path = Path(__file__).parent / "audit.log"
    log_path.touch(exist_ok=True)
    try:
        mode = log_path.stat().st_mode
        if mode & stat.S_IWOTH:
            print(
                "[SECURITY ERROR] audit.log es world-writable. Corrigiendo permisos.",
                file=sys.stderr,
            )
        # 0o600 — owner read/write only; best-effort on Windows
        os.chmod(log_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    # 3. Warn if .env is readable by group or others
    env_path = Path(".env")
    if env_path.exists():
        try:
            mode = env_path.stat().st_mode
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                print(
                    "[SECURITY WARNING] .env es legible por otros usuarios. "
                    "Ejecutar: chmod 600 .env",
                    file=sys.stderr,
                )
        except OSError:
            pass


def main():
    _startup_security_checks(settings)
    mcp.run(transport=settings.mcp_transport)


if __name__ == "__main__":
    main()
