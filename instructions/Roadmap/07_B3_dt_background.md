# Tarea 07 — B3: Tool analyze_project_vulnerabilities (Velocidad 2)

**Archivo a crear:** `zeronoise/tools/dt_background.py`
**Modificar:** `zeronoise/server.py` (2 líneas)
**Tiempo estimado:** 25 minutos
**Dependencias:** Ninguna — usa tools MCP existentes

---

## Problema

No existe un orquestador de alto nivel para el flujo DT → Stage 2 → Stage 3.
El agente de Teams no puede invocar un flujo completo con una sola llamada.
`run_reachability_filter` hace Stage 2 pero no Stage 3 ni VEX.

## Crear `zeronoise/tools/dt_background.py`

```python
"""
dt_background.py — MCP tool: analyze_project_vulnerabilities

Orquestador del flujo completo de análisis background desde Dependency-Track.
Equivalente a analyze_depcheck_report pero con fuente en DT.

Diseñado para:
  - Agente corporativo en Teams / Copilot Studio (Velocidad 2)
  - Scheduler automático nocturno (B6)
  - Análisis manual de proyectos ya enviados a DT

Registro en server.py:
    from zeronoise.tools.dt_background import analyze_project_vulnerabilities
    mcp.tool()(analyze_project_vulnerabilities)
"""
from __future__ import annotations
from typing import Optional

from zeronoise.audit import audit_tool, safe_tool
from zeronoise.config import get_settings


@safe_tool
@audit_tool(side_effects="conditional")
async def analyze_project_vulnerabilities(
    project_uuid: str,
    project_path: str,
    max_findings: int = 20,
    severity_filter: str = "HIGH",
    dry_run: bool = True,
    offset: int = 0,
) -> dict:
    """
    Analiza todas las vulnerabilidades pendientes de un proyecto en DT.

    Flujo:
      1. get_actionable_findings — obtiene vulns pendientes de DT
      2. Filtra por severidad
      3. Para cada finding: Stage 2 (reachability, 0 tokens)
      4. Para REACHABLE con confianza >= threshold: Stage 3 (LLM)
      5. update_finding_analysis — escribe en DT si dry_run=False
      6. generate_vex_report — reporte final

    Args:
        project_uuid:     UUID del proyecto en Dependency-Track
        project_path:     Ruta absoluta al código fuente del proyecto
        max_findings:     Máximo de findings a analizar en esta sesión (default 20)
                          Controla el costo de tokens en Stage 3
        severity_filter:  CRITICAL | HIGH | MEDIUM | LOW | ALL
                          "HIGH" analiza CRITICAL + HIGH
        dry_run:          Si True, no escribe en DT. Default: True
        offset:           Para paginación — continuar desde este índice

    Returns:
        {
          "project_name": str,
          "pipeline_decision": "PROMOTE" | "BLOCK" | "REVIEW",
          "summary": { total_actionable, analyzed, remaining,
                       not_reachable, reachable, exploitable,
                       noise_reduction_pct, tokens_used },
          "verdicts": [...],
          "vex_report": {...},
          "continuation_hint": str | null,
          "dry_run": bool,
        }
    """
    from zeronoise.tools._validators import _validate_uuid, _validate_project_path
    from zeronoise.tools.sbom_ingestion import get_actionable_findings
    from zeronoise.tools.reachability import analyze_package_reachability
    from zeronoise.tools.stage3_context import prepare_stage3_context
    from zeronoise.tools.decision import generate_finding_verdict, generate_vex_report
    from zeronoise.tools.reachability import update_finding_analysis

    settings = get_settings()

    # Validaciones
    try:
        _validate_uuid(project_uuid, "project_uuid")
        _validate_project_path(project_path)
    except ValueError as e:
        return {"error": "validation_error", "message": str(e)}

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    filter_upper = severity_filter.upper()

    if filter_upper == "ALL":
        allowed_severities = set(severity_order)
    elif filter_upper in severity_order:
        idx = severity_order.index(filter_upper)
        allowed_severities = set(severity_order[:idx + 1])
    else:
        return {"error": "validation_error",
                "message": f"severity_filter inválido: {severity_filter}"}

    # Stage 1 — obtener findings de DT
    findings_resp = await get_actionable_findings(
        project_uuid=project_uuid,
        offset=offset,
    )
    if "error" in findings_resp:
        return findings_resp

    project_name = findings_resp.get("project", {}).get("name", "unknown")
    all_findings = findings_resp.get("findings", [])
    total_actionable = findings_resp.get("total_findings", len(all_findings))

    # Filtrar por severidad
    filtered = [
        f for f in all_findings
        if f.get("vulnerability", {}).get("severity", "").upper() in allowed_severities
    ]

    # Limitar a max_findings
    to_analyze = filtered[:max_findings]
    remaining = max(0, len(filtered) - max_findings)

    if not to_analyze:
        return {
            "project_name": project_name,
            "pipeline_decision": "PROMOTE",
            "summary": {
                "total_actionable": total_actionable,
                "analyzed": 0,
                "remaining": 0,
                "not_reachable": 0,
                "reachable": 0,
                "exploitable": 0,
                "noise_reduction_pct": 0.0,
                "tokens_used": "Stage 3 no ejecutado — sin findings en el filtro",
            },
            "verdicts": [],
            "vex_report": None,
            "continuation_hint": None,
            "dry_run": dry_run,
        }

    # Stage 2 + Stage 3 por finding
    verdicts = []
    stage3_count = 0
    block_reasons = []

    for finding in to_analyze:
        component = finding.get("component", {})
        vuln = finding.get("vulnerability", {})
        purl = component.get("purl", "")
        cve_id = vuln.get("vulnId", "")
        severity = vuln.get("severity", "MEDIUM")
        description = vuln.get("description", "")[:500]
        cvss = vuln.get("cvssV3BaseScore") or vuln.get("cvssV2BaseScore")
        component_uuid = component.get("uuid", "")
        vuln_uuid = vuln.get("uuid", "")

        entry = {
            "cve_id": cve_id,
            "package": component.get("name", ""),
            "purl": purl,
            "severity": severity,
            "verdict": "UNKNOWN",
            "justification": "",
            "stage3_used": False,
            "component_uuid": component_uuid,
            "vuln_uuid": vuln_uuid,
        }

        if not purl:
            entry["justification"] = "Sin PURL — no se puede ejecutar reachability"
            verdicts.append(entry)
            continue

        # Stage 2
        try:
            reach = await analyze_package_reachability(
                package_name=purl,
                project_path=project_path,
            )
        except Exception as e:
            entry["justification"] = f"Error Stage 2: {e}"
            verdicts.append(entry)
            continue

        is_reachable = reach.get("is_reachable", False)
        confidence = float(reach.get("confidence", 0.0))
        entry["stage2_result"] = reach

        if not is_reachable:
            entry["verdict"] = "NOT_REACHABLE"
            entry["justification"] = (
                f"'{purl}' nunca es importado en el código fuente. "
                f"{cve_id} no es explotable en este proyecto."
            )
            if not dry_run and component_uuid and vuln_uuid:
                await update_finding_analysis(
                    project_uuid=project_uuid,
                    component_uuid=component_uuid,
                    vulnerability_uuid=vuln_uuid,
                    state="NOT_AFFECTED",
                    details=f"[ZeroNoise Stage 2] {entry['justification']}",
                )
            verdicts.append(entry)
            continue

        if confidence < settings.stage3_confidence_threshold:
            entry["verdict"] = "REACHABLE"
            entry["justification"] = (
                f"Alcanzable pero confianza ({confidence:.0%}) < umbral Stage 3. "
                f"Requiere revisión humana."
            )
            verdicts.append(entry)
            continue

        # Stage 3
        entry["stage3_used"] = True
        stage3_count += 1
        try:
            context = await prepare_stage3_context(
                package_name=purl,
                project_path=project_path,
                vulnerability_id=cve_id,
                severity=severity,
                vulnerability_description=description,
                cvss=cvss,
                vulnerable_functions=vuln.get("vulnerableFunctions", []) or [],
            )
            verdict_result = await generate_finding_verdict(
                finding_id=f"{component_uuid}:{vuln_uuid}",
                verdict=context.get("pre_analysis_signals", {}).get("risk_signal", "REACHABLE"),
                justification="CODE_NOT_REACHABLE",
                confidence=confidence,
                evidence=reach.get("usages", []),
                analysis_details=str(context.get("pre_analysis_signals", {})),
            )
            entry["verdict"] = verdict_result.get("verdict", "REACHABLE")
            entry["justification"] = verdict_result.get("justification", "")

            if not dry_run and component_uuid and vuln_uuid:
                dt_state = verdict_result.get("dt_analysis_state", "IN_TRIAGE")
                await update_finding_analysis(
                    project_uuid=project_uuid,
                    component_uuid=component_uuid,
                    vulnerability_uuid=vuln_uuid,
                    state=dt_state,
                    details=f"[ZeroNoise Stage 3] {entry['justification']}",
                )
        except Exception as e:
            entry["verdict"] = "REACHABLE"
            entry["justification"] = f"Stage 3 falló: {e}. Requiere revisión humana."

        if entry["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
            block_reasons.append(f"{cve_id}: {entry['justification'][:150]}")

        verdicts.append(entry)

    # VEX
    vex = None
    try:
        vex = await generate_vex_report(
            project_name=project_name,
            project_version="1.0",
            findings=[{
                "vuln_id": v["cve_id"],
                "purl": v["purl"],
                "verdict": v["verdict"],
                "justification": "CODE_NOT_REACHABLE",
                "analysis_details": v["justification"],
                "confidence": 0.9,
            } for v in verdicts],
        )
    except Exception:
        pass

    not_reachable = sum(1 for v in verdicts if v["verdict"] == "NOT_REACHABLE")
    noise_pct = round(not_reachable / len(verdicts) * 100, 1) if verdicts else 0.0
    pipeline_decision = "BLOCK" if block_reasons else "PROMOTE"

    continuation = None
    if remaining > 0:
        next_offset = offset + max_findings
        continuation = (
            f"Quedan {remaining} findings sin analizar. "
            f"Llamar con offset={next_offset} para continuar."
        )

    return {
        "project_name": project_name,
        "pipeline_decision": pipeline_decision,
        "summary": {
            "total_actionable": total_actionable,
            "analyzed": len(verdicts),
            "remaining": remaining,
            "not_reachable": not_reachable,
            "reachable": sum(1 for v in verdicts if v["verdict"] == "REACHABLE"),
            "exploitable": sum(1 for v in verdicts
                               if v["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE")),
            "noise_reduction_pct": noise_pct,
            "tokens_used": f"Stage 3 ejecutado para {stage3_count}/{len(verdicts)} findings",
        },
        "verdicts": verdicts,
        "vex_report": vex,
        "block_reason": " | ".join(block_reasons) if block_reasons else None,
        "continuation_hint": continuation,
        "dry_run": dry_run,
    }
```

## Registrar en `server.py`

Agregar estas **dos líneas exactas** en `server.py`, junto a los demás registros:

```python
from zeronoise.tools.dt_background import analyze_project_vulnerabilities
mcp.tool()(analyze_project_vulnerabilities)
```

## Verificar

```bash
python -c "from zeronoise.tools.dt_background import analyze_project_vulnerabilities; print('OK')"
```

## Lo que NO tocar

`tools/reachability.py`, `tools/stage3_context.py`, `tools/decision.py` — sin cambios.
Solo agregar las dos líneas en `server.py`.
