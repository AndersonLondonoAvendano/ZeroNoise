# Tarea 10 — B7: Notificaciones Teams webhook

**Archivo a crear:** `zeronoise/clients/notifier.py`
**Tiempo estimado:** 15 minutos
**Dependencias:** Tarea 07 implementada (para integrar en dt_background)

---

## Problema

Cuando ZeroNoise detecta un `EXPLOITABLE`, el resultado queda en `audit.log` y en DT
pero nadie recibe una alerta. El equipo de seguridad no se entera en tiempo real.

## 1. Agregar en `.env.example`

```env
# Notificaciones — opcional
WEBHOOK_URL=          # Teams incoming webhook URL (dejar vacío para deshabilitar)
NOTIFY_ON=EXPLOITABLE # EXPLOITABLE | LIKELY_EXPLOITABLE | ALL
```

## 2. Agregar en `config.py`

```python
webhook_url: str = ""
notify_on: str = "EXPLOITABLE"   # EXPLOITABLE | LIKELY_EXPLOITABLE | ALL
```

## 3. Crear `zeronoise/clients/notifier.py`

```python
"""
notifier.py — Notificaciones cuando ZeroNoise detecta EXPLOITABLE.

Soporta webhooks genéricos compatibles con Teams, Slack y Discord.

Configurar WEBHOOK_URL en .env con la URL del canal de notificaciones.

Para Teams:
  Canal → Conectores → Incoming Webhook → copiar URL → pegar en WEBHOOK_URL
"""
from __future__ import annotations
import httpx
from zeronoise.config import get_settings


async def notify_if_needed(
    verdict: str,
    project_name: str,
    cve_id: str,
    package: str,
    justification: str,
    cvss_score: float | None = None,
) -> None:
    """
    Envía notificación si el veredicto supera el umbral configurado.
    Si WEBHOOK_URL está vacío, no hace nada silenciosamente.
    """
    settings = get_settings()
    if not settings.webhook_url:
        return

    should_notify = _should_notify(verdict, settings.notify_on)
    if not should_notify:
        return

    payload = _build_payload(
        verdict=verdict,
        project_name=project_name,
        cve_id=cve_id,
        package=package,
        justification=justification,
        cvss_score=cvss_score,
    )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(settings.webhook_url, json=payload)
    except Exception:
        pass  # Notificaciones son best-effort — no bloquear el análisis


def _should_notify(verdict: str, notify_on: str) -> bool:
    v = verdict.upper()
    n = notify_on.upper()
    if n == "ALL":
        return v in ("EXPLOITABLE", "LIKELY_EXPLOITABLE", "REACHABLE")
    if n == "LIKELY_EXPLOITABLE":
        return v in ("EXPLOITABLE", "LIKELY_EXPLOITABLE")
    return v == "EXPLOITABLE"


def _build_payload(
    verdict: str,
    project_name: str,
    cve_id: str,
    package: str,
    justification: str,
    cvss_score: float | None,
) -> dict:
    """
    Construye el payload. Compatible con Teams Incoming Webhook (MessageCard).
    También funciona con Slack y Discord (formato similar).
    """
    color = "FF0000" if verdict == "EXPLOITABLE" else "FF8C00"
    icon = "🔴" if verdict == "EXPLOITABLE" else "🟠"
    cvss_str = f" | CVSS: {cvss_score}" if cvss_score else ""

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": f"ZeroNoise — {verdict} en {project_name}",
        "sections": [{
            "activityTitle": f"{icon} ZeroNoise detectó **{verdict}**",
            "activitySubtitle": f"Proyecto: **{project_name}**",
            "facts": [
                {"name": "CVE", "value": cve_id},
                {"name": "Paquete", "value": package},
                {"name": "Severidad", "value": f"{verdict}{cvss_str}"},
                {"name": "Justificación", "value": justification[:300]},
            ],
            "markdown": True,
        }],
    }
```

## 4. Integrar en `tools/dt_background.py`

En `analyze_project_vulnerabilities`, después de agregar el entry al bloque de
EXPLOITABLE, agregar la llamada al notifier:

```python
if entry["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
    block_reasons.append(...)

    # Notificar al equipo de seguridad
    from zeronoise.clients.notifier import notify_if_needed
    await notify_if_needed(
        verdict=entry["verdict"],
        project_name=project_name,
        cve_id=cve_id,
        package=entry.get("package", ""),
        justification=entry.get("justification", ""),
        cvss_score=cvss,
    )
```

Hacer lo mismo en `tools/depcheck_gate.py` en el bloque equivalente.

## Verificar

```bash
# Test manual del notifier (requiere WEBHOOK_URL en .env)
python -c "
import asyncio
from zeronoise.clients.notifier import notify_if_needed
asyncio.run(notify_if_needed(
    verdict='EXPLOITABLE',
    project_name='microservicio-clientes',
    cve_id='CVE-2026-33871',
    package='netty-resolver-dns',
    justification='Prueba de notificación ZeroNoise',
    cvss_score=7.5,
))
print('Notificación enviada (revisar Teams)')
"
```

## Lo que NO tocar

`audit.py`, `tools/decision.py` — sin cambios.
