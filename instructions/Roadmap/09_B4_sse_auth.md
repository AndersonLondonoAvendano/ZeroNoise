# Tarea 09 — B4: SSE con API Key y endpoint /health

**Archivos a modificar:** `main.py`, `config.py`, `.env.example`
**Tiempo estimado:** 20 minutos
**Dependencias:** Ninguna

---

## Problema

ZeroNoise tiene `MCP_TRANSPORT=sse` preparado pero sin autenticación ni health check.
Copilot Studio no puede conectarse a un servidor MCP sin HTTPS + auth.

## 1. Agregar campos en `config.py`

En la clase `Settings`, agregar junto a los campos existentes:

```python
zeronoise_api_key: str = ""      # Requerido si MCP_TRANSPORT=sse
mcp_host: str = "127.0.0.1"     # 0.0.0.0 para exponer externamente
mcp_port: int = 8000
```

## 2. Agregar al `.env.example`

```env
# SSE — solo relevante si MCP_TRANSPORT=sse
MCP_HOST=127.0.0.1
MCP_PORT=8000
ZERONOISE_API_KEY=    # generar: python -c "import secrets; print(secrets.token_hex(32))"
```

## 3. Modificar `main.py`

Buscar el bloque donde se levanta el servidor SSE (cuando `settings.mcp_transport == "sse"`)
y agregar el middleware y el endpoint de health:

```python
# Agregar estos imports al inicio de main.py (solo si no existen ya):
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.applications import Starlette

# Reemplazar o envolver el arranque SSE con:
if settings.mcp_transport == "sse":

    # Validar que hay API key configurada si se expone fuera de localhost
    if settings.mcp_host != "127.0.0.1" and not settings.zeronoise_api_key:
        print(
            "[SECURITY WARNING] MCP_HOST no es localhost pero ZERONOISE_API_KEY está vacío. "
            "El servidor MCP queda expuesto sin autenticación.",
            file=sys.stderr,
        )

    class ApiKeyMiddleware(BaseHTTPMiddleware):
        """Valida X-API-Key en todas las requests excepto /health."""

        async def dispatch(self, request, call_next):
            if request.url.path == "/health":
                return await call_next(request)

            # Si no hay API key configurada, no requerir auth (modo dev local)
            if not settings.zeronoise_api_key:
                return await call_next(request)

            api_key = request.headers.get("X-API-Key", "")
            if api_key != settings.zeronoise_api_key:
                return JSONResponse(
                    {"error": "Unauthorized", "message": "X-API-Key inválido o ausente"},
                    status_code=401,
                )
            return await call_next(request)

    # Obtener la app ASGI de FastMCP y agregarle el middleware
    # (la forma exacta depende de la versión de FastMCP instalada —
    #  verificar que mcp tiene atributo .app o similar)
    app = mcp.get_asgi_app()          # ← ajustar según la API de FastMCP
    app.add_middleware(ApiKeyMiddleware)

    # Agregar endpoint /health
    async def health(request):
        return JSONResponse({
            "status": "ok",
            "server": "zeronoise",
            "transport": "sse",
            "version": "1.0",
        })

    # Montar /health en la app (forma Starlette)
    app.routes.append(Route("/health", health))

    import uvicorn
    uvicorn.run(
        app,
        host=settings.mcp_host,
        port=settings.mcp_port,
        log_level="info",
    )
```

> **Nota para Claude Code:** La API exacta para obtener la app ASGI de FastMCP
> puede variar. Revisar `mcp.sse_app()`, `mcp.asgi_app()` o `mcp.get_asgi_app()`
> según la versión instalada. Verificar con:
> `python -c "import fastmcp; print(dir(fastmcp.FastMCP))"`

## 4. Para PoC inmediata sin infraestructura (ngrok)

```bash
# Terminal 1 — levantar ZeroNoise en modo SSE
MCP_TRANSPORT=sse MCP_HOST=0.0.0.0 MCP_PORT=8000 uv run python main.py

# Terminal 2 — exponer con ngrok
ngrok http 8000

# Copilot Studio:
# URL del servidor: https://xxxx.ngrok.io/sse
# Autenticación: Clave de API
# Header: X-API-Key: [valor de ZERONOISE_API_KEY]
```

## Verificar

```bash
# Health check
curl http://localhost:8000/health

# Con API key
curl -H "X-API-Key: tu_api_key" http://localhost:8000/sse

# Sin API key (debe retornar 401)
curl http://localhost:8000/sse
```

## Lo que NO tocar

El flujo stdio (`MCP_TRANSPORT=stdio`) — no modificar, debe seguir funcionando igual.
