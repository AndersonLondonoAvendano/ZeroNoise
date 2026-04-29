# Tarea 12 — B6: Scheduler de análisis background automático

**Archivos a crear:** `zeronoise/scheduler.py`, `project_paths.json`
**Modificar:** `main.py` (arranque del loop)
**Tiempo estimado:** 20 minutos
**Dependencias:** Tareas 07 y 11 implementadas

---

## Problema

La Velocidad 2 requiere intervención humana. Para una organización con múltiples
proyectos en DT, lo ideal es que ZeroNoise corra automáticamente sin que nadie
tenga que dispararlo.

## 1. Agregar en `.env.example`

```env
# Scheduler — análisis background automático
SCHEDULER_ENABLED=false
SCHEDULER_INTERVAL_HOURS=24
SCHEDULER_MAX_FINDINGS_PER_RUN=50
SCHEDULER_SEVERITY_FILTER=HIGH     # CRITICAL | HIGH | MEDIUM | LOW | ALL
```

## 2. Agregar en `config.py`

```python
scheduler_enabled: bool = False
scheduler_interval_hours: int = 24
scheduler_max_findings_per_run: int = 50
scheduler_severity_filter: str = "HIGH"
```

## 3. Crear `project_paths.json` en la raíz del proyecto

Mapeo de UUID de DT a configuración del proyecto. ZeroNoise lo lee para saber
qué proyectos analizar en cada ciclo del scheduler.

```json
{
  "0dd02b59-c900-4bdd-bfda-6539ec040562": {
    "name": "clientes",
    "project_path": "C:\\Users\\admin\\Desktop\\ZeroNoise\\vuln_projects\\clientes-develop\\microservicio-clientes",
    "repo_path": "",
    "enabled": true
  },
  "ce2cf25e-25ef-44d5-b3e6-4e1ef708b190": {
    "name": "WebGoat",
    "project_path": "",
    "repo_path": "security/webgoat",
    "enabled": false
  },
  "2119d351-320a-4565-b2bb-20e07073edc7": {
    "name": "nodejs-goof",
    "project_path": "",
    "repo_path": "",
    "enabled": false
  }
}
```

Agregar `project_paths.json` al `.gitignore` — contiene rutas locales.

## 4. Crear `zeronoise/scheduler.py`

```python
"""
scheduler.py — Análisis background periódico de todos los proyectos en DT.

Se activa si SCHEDULER_ENABLED=true en .env.
Corre como tarea asyncio dentro del mismo proceso del servidor MCP SSE.
No requiere cron externo ni proceso separado.

Ciclo:
  1. Cargar project_paths.json
  2. Para cada proyecto enabled: llamar analyze_project_vulnerabilities
  3. Si hay EXPLOITABLE: notificar (si WEBHOOK_URL configurado)
  4. Loggear resumen en audit.log
  5. Dormir SCHEDULER_INTERVAL_HOURS horas y repetir
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("zeronoise.scheduler")


async def start_scheduler() -> None:
    """
    Arranca el loop del scheduler. Llamar desde main.py como tarea asyncio.
    No retorna — corre indefinidamente hasta que el proceso termina.
    """
    from zeronoise.config import get_settings
    settings = get_settings()

    if not settings.scheduler_enabled:
        return

    logger.info(
        f"Scheduler iniciado — intervalo: {settings.scheduler_interval_hours}h, "
        f"severidad: {settings.scheduler_severity_filter}"
    )

    while True:
        await asyncio.sleep(settings.scheduler_interval_hours * 3600)
        try:
            await _run_cycle()
        except Exception as e:
            logger.error(f"Error en ciclo del scheduler: {e}")


async def _run_cycle() -> None:
    """Un ciclo completo de análisis."""
    from zeronoise.config import get_settings
    from zeronoise.tools.dt_background import analyze_project_vulnerabilities
    from zeronoise.clients.notifier import notify_if_needed

    settings = get_settings()
    projects = _load_project_paths()

    if not projects:
        logger.warning("project_paths.json vacío o no encontrado — nada que analizar")
        return

    timestamp = datetime.now(timezone.utc).isoformat()
    logger.info(f"Ciclo scheduler iniciado: {timestamp} — {len(projects)} proyectos")

    for uuid, config in projects.items():
        if not config.get("enabled", False):
            continue

        project_path = config.get("project_path", "")
        repo_path = config.get("repo_path", "")
        name = config.get("name", uuid[:8])

        if not project_path and not repo_path:
            logger.warning(f"Proyecto '{name}' sin project_path ni repo_path — omitido")
            continue

        logger.info(f"Analizando: {name} ({uuid[:8]}...)")

        try:
            result = await analyze_project_vulnerabilities(
                project_uuid=uuid,
                project_path=project_path,
                max_findings=settings.scheduler_max_findings_per_run,
                severity_filter=settings.scheduler_severity_filter,
                dry_run=False,   # El scheduler APLICA los verdicts
            )

            summary = result.get("summary", {})
            logger.info(
                f"{name}: analizados={summary.get('analyzed', 0)}, "
                f"not_reachable={summary.get('not_reachable', 0)}, "
                f"exploitable={summary.get('exploitable', 0)}, "
                f"noise_reduction={summary.get('noise_reduction_pct', 0)}%"
            )

            # Notificar exploitables
            for v in result.get("verdicts", []):
                if v.get("verdict") in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
                    await notify_if_needed(
                        verdict=v["verdict"],
                        project_name=name,
                        cve_id=v.get("cve_id", ""),
                        package=v.get("package", ""),
                        justification=v.get("justification", ""),
                    )

        except Exception as e:
            logger.error(f"Error analizando {name}: {e}")


def _load_project_paths() -> dict:
    """Carga project_paths.json. Retorna {} si no existe."""
    path = Path("project_paths.json")
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
```

## 5. Integrar en `main.py`

Buscar la función principal de arranque y agregar la tarea del scheduler:

```python
# Al final de main.py, antes o dentro del arranque del servidor:
import asyncio
from zeronoise.scheduler import start_scheduler
from zeronoise.config import get_settings

settings = get_settings()

if settings.scheduler_enabled:
    # Crear tarea asyncio para el scheduler
    # (el servidor MCP SSE también corre en el loop de asyncio)
    asyncio.get_event_loop().create_task(start_scheduler())
```

> **Nota para Claude Code:** La forma exacta de integrar depende de cómo FastMCP
> gestiona el event loop en `main.py`. Si usa `asyncio.run()`, el scheduler debe
> arrancarse dentro del mismo coroutine. Si usa uvicorn, usar `lifespan` de Starlette.

## Verificar

```bash
# Probar un ciclo manual sin esperar el intervalo
python -c "
import asyncio
from zeronoise.scheduler import _run_cycle
asyncio.run(_run_cycle())
"
```

## Lo que NO tocar

`tools/dt_background.py` — el scheduler lo invoca, no lo modifica.
`audit.log` — el scheduler usa el logger estándar, no escribe directamente.
