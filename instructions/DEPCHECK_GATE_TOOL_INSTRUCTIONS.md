# ZeroNoise — Instrucciones: Fast-Gate Tool + POC para Dep-Check

> **Propósito:** Conectar el `DepCheckIngester` (ya implementado) con el pipeline de
> Stage 2 → Stage 3 existente, y crear un script POC para probarlo desde terminal.
> El resultado es un nuevo punto de entrada: el reporte JSON de dep-check activa
> ZeroNoise igual que un prompt de DT, pero con la fuente de datos diferente.
>
> **Prerequisito:** `clients/depcheck_ingester.py` y `models/depcheck_finding.py`
> ya deben estar implementados antes de ejecutar estas instrucciones.

---

## Qué existe vs. qué falta

### Ya existe ✅
- `clients/depcheck_ingester.py` — lee y normaliza el reporte JSON
- `models/depcheck_finding.py` — modelo `DepCheckFinding` con `effective_purl`, `can_run_reachability`
- `tools/reachability.py` — `analyze_package_reachability(package_purl, project_path)` 
- `tools/stage3_context.py` — `prepare_stage3_context(package_name, vulnerability_id, vulnerable_functions, project_path)`
- `tools/decision.py` — `generate_finding_verdict(...)` y `generate_vex_report(...)`
- `tools/_validators.py` — validación compartida
- `audit.py` — decorators `@safe_tool` y `@audit_tool`

### Falta implementar 🔧
1. `tools/depcheck_gate.py` — MCP tool `analyze_depcheck_report` que orquesta el flujo completo
2. `scripts/poc_depcheck.py` — POC standalone para probar desde terminal
3. Registro en `server.py` — una línea
4. Nuevos comandos en `CLAUDE.md`

---

## 1. MCP Tool — `tools/depcheck_gate.py`

Crear este archivo. Es el orquestador del flujo dep-check → Stage 2 → Stage 3.

**Lógica central:**
```
DepCheckIngester.load()
        ↓
filter_by_cvss(threshold)  →  gate_blockers (1-5 CVEs típicamente)
        ↓
Deduplicar por PURL (mismo paquete, múltiples CVEs → un scan)
        ↓
Para cada CVE único:
  ¿can_run_reachability? 
    SÍ  → analyze_package_reachability() → Stage 2
    NO  → verdict UNKNOWN, requires_human_review=True
        ↓
  ¿Stage 2 = REACHABLE y confidence >= threshold?
    SÍ  → prepare_stage3_context() + generate_finding_verdict()
    NO  → verdict NOT_REACHABLE (0 tokens)
        ↓
generate_vex_report() con todos los verdicts
        ↓
pipeline_decision: PROMOTE | BLOCK
```

```python
"""
depcheck_gate.py — MCP tool: analyze_depcheck_report

Punto de entrada para el flujo dep-check → Stage 2 → Stage 3.
Consume el reporte JSON de OWASP Dependency-Check y retorna un
pipeline_decision: PROMOTE | BLOCK con justificación por CVE.

Registro en server.py:
    from zeronoise.tools.depcheck_gate import analyze_depcheck_report
    mcp.tool()(analyze_depcheck_report)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from zeronoise.audit import audit_tool, safe_tool
from zeronoise.clients.depcheck_ingester import DepCheckIngester
from zeronoise.models.depcheck_finding import DepCheckFinding, PurlConfidence
from zeronoise.config import get_settings


@safe_tool
@audit_tool(side_effects="conditional")
async def analyze_depcheck_report(
    report_path: str,
    project_path: str,
    cvss_threshold: Optional[float] = None,
    dry_run: bool = True,
) -> dict:
    """
    Analiza el reporte JSON de OWASP Dependency-Check y determina si el pipeline
    puede continuar (PROMOTE) o debe detenerse (BLOCK).

    Flujo:
      1. Lee el reporte y filtra findings con CVSS >= cvss_threshold
      2. Para cada finding: Stage 2 (reachability, 0 tokens)
      3. Solo si REACHABLE: Stage 3 (LLM, consume tokens)
      4. Genera VEX report con todos los verdicts
      5. Retorna pipeline_decision: PROMOTE | BLOCK

    Args:
        report_path:     Ruta absoluta al reporte JSON de dep-check.
                         En CI: el artefacto generado por sast_dependency_check.
        project_path:    Ruta absoluta al código fuente del proyecto.
                         En CI: $CI_PROJECT_DIR
        cvss_threshold:  CVSS mínimo para considerar gate blocker.
                         Default: GATE_CVSS_THRESHOLD del .env (7.0)
        dry_run:         Si True, no escribe verdicts en DT. Default: True.

    Returns:
        {
          "pipeline_decision": "PROMOTE" | "BLOCK",
          "summary": {
            "gate_blockers_found": int,
            "not_reachable": int,       ← resueltos automáticamente (0 tokens)
            "reachable": int,           ← analizados por LLM
            "exploitable": int,         ← razón del BLOCK si aplica
            "unknown": int,             ← requieren revisión humana
            "tokens_used": "Stage 3 ejecutado para N/M findings"
          },
          "verdicts": [ ... ],          ← detalle por CVE
          "vex_report": { ... },        ← OpenVEX completo
          "block_reason": str | null,
          "promote_reason": str | null,
        }

    Contrato MCP:
        read_only: false (escribe en DT si dry_run=False)
        side_effects: conditional
        requires_confirmation: false (el pipeline lo invoca automáticamente)
        expected_cost: low-to-moderate (Stage 3 solo para findings REACHABLE)
    """
    settings = get_settings()
    threshold = cvss_threshold if cvss_threshold is not None else settings.gate_cvss_threshold

    # --- Validaciones de entrada ---
    # (reutilizar _validators si está disponible, o validar inline)
    report_file = Path(report_path)
    if not report_file.exists():
        return {
            "error": "validation_error",
            "message": f"Reporte no encontrado: {report_path}",
        }
    if not report_file.suffix == ".json":
        return {
            "error": "validation_error",
            "message": f"El reporte debe ser un archivo JSON: {report_path}",
        }

    project_dir = Path(project_path)
    if not project_dir.is_absolute():
        return {
            "error": "validation_error",
            "message": f"project_path debe ser absoluto: {project_path}",
        }
    if not project_dir.exists():
        return {
            "error": "validation_error",
            "message": f"project_path no existe: {project_path}",
        }

    # --- Stage 0: Ingestar reporte ---
    ingester = DepCheckIngester(report_path)
    report_meta = ingester.get_report_metadata()
    all_findings = ingester.load()
    gate_blockers = ingester.filter_by_cvss(all_findings, threshold)

    if not gate_blockers:
        return {
            "pipeline_decision": "PROMOTE",
            "summary": {
                "gate_blockers_found": 0,
                "not_reachable": 0,
                "reachable": 0,
                "exploitable": 0,
                "unknown": 0,
                "tokens_used": "Stage 3 no ejecutado — no hay gate blockers",
            },
            "verdicts": [],
            "vex_report": None,
            "block_reason": None,
            "promote_reason": (
                f"No se encontraron findings con CVSS >= {threshold} "
                f"en el reporte de dep-check. "
                f"({report_meta['dependencies_with_vulns']} deps con vulns, "
                f"ninguna supera el umbral)"
            ),
            "report_metadata": report_meta,
        }

    # --- Análisis por finding ---
    verdicts = []
    stage3_count = 0
    block_reasons = []

    # Importar tools de stages existentes
    # (imports tardíos para evitar circularidad y solo cargar si hay findings)
    from zeronoise.tools.reachability import analyze_package_reachability
    from zeronoise.tools.stage3_context import prepare_stage3_context
    from zeronoise.tools.decision import generate_finding_verdict, generate_vex_report

    for finding in gate_blockers:
        verdict_entry = await _analyze_finding(
            finding=finding,
            project_path=project_path,
            dry_run=dry_run,
            stage3_threshold=settings.stage3_confidence_threshold,
            analyze_package_reachability=analyze_package_reachability,
            prepare_stage3_context=prepare_stage3_context,
            generate_finding_verdict=generate_finding_verdict,
        )
        verdicts.append(verdict_entry)

        if verdict_entry["stage3_used"]:
            stage3_count += 1

        if verdict_entry["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
            block_reasons.append(
                f"{finding.cve_id} ({finding.primary_package.artifact_name if finding.primary_package else 'unknown'}): "
                f"{verdict_entry['justification'][:200]}"
            )

    # --- Generar VEX ---
    vex = None
    try:
        verdict_dicts = [
            {
                "cve_id": v["cve_id"],
                "verdict": v["verdict"],
                "justification": v["justification"],
                "package": v["package"],
            }
            for v in verdicts
        ]
        vex = await generate_vex_report(
            project_name=report_meta.get("project_name", "unknown"),
            findings=verdict_dicts,
        )
    except Exception:
        pass  # VEX es best-effort — no bloquear el pipeline por esto

    # --- Decisión final ---
    pipeline_decision = "BLOCK" if block_reasons else "PROMOTE"

    counts = {
        "not_reachable": sum(1 for v in verdicts if v["verdict"] == "NOT_REACHABLE"),
        "reachable": sum(1 for v in verdicts if v["verdict"] in ("REACHABLE", "FALSE_POSITIVE")),
        "exploitable": sum(1 for v in verdicts if v["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE")),
        "unknown": sum(1 for v in verdicts if v["verdict"] == "UNKNOWN"),
    }

    return {
        "pipeline_decision": pipeline_decision,
        "summary": {
            "gate_blockers_found": len(gate_blockers),
            **counts,
            "tokens_used": f"Stage 3 ejecutado para {stage3_count}/{len(gate_blockers)} findings",
        },
        "verdicts": verdicts,
        "vex_report": vex,
        "block_reason": " | ".join(block_reasons) if block_reasons else None,
        "promote_reason": (
            "Todos los gate blockers son NOT_REACHABLE o FALSE_POSITIVE"
            if pipeline_decision == "PROMOTE" else None
        ),
        "report_metadata": report_meta,
        "dry_run": dry_run,
    }


async def _analyze_finding(
    finding: DepCheckFinding,
    project_path: str,
    dry_run: bool,
    stage3_threshold: float,
    analyze_package_reachability,
    prepare_stage3_context,
    generate_finding_verdict,
) -> dict:
    """Analiza un único DepCheckFinding. Retorna el dict de veredicto."""

    base = {
        "cve_id": finding.cve_id,
        "package": (
            finding.primary_package.artifact_name
            if finding.primary_package else "unknown"
        ),
        "cvss_score": finding.cvss.score if finding.cvss else None,
        "cvss_source": finding.cvss.source.value if finding.cvss else None,
        "purl": finding.effective_purl,
        "purl_confidence": (
            finding.primary_package.purl_confidence.value
            if finding.primary_package else "UNAVAILABLE"
        ),
        "affected_jars": [p.file_name for p in finding.affected_packages],
        "identification_issues": finding.identification_issues,
        "requires_human_review": finding.requires_human_review,
        "verdict": "UNKNOWN",
        "justification": "",
        "stage3_used": False,
    }

    # Sin PURL → no se puede hacer reachability determinístico
    if not finding.can_run_reachability:
        base["verdict"] = "UNKNOWN"
        base["justification"] = (
            f"PURL no disponible con confianza suficiente para '{base['package']}'. "
            f"Dep-check no pudo identificar el paquete exacto (fat JAR o artifact desconocido). "
            f"Requiere revisión humana — no se bloquea automáticamente."
        )
        return base

    # --- Stage 2: Reachability (0 tokens) ---
    try:
        reachability = await analyze_package_reachability(
            package_purl=finding.effective_purl,
            project_path=project_path,
        )
    except Exception as e:
        base["verdict"] = "UNKNOWN"
        base["justification"] = f"Error en Stage 2 para {finding.effective_purl}: {e}"
        return base

    is_reachable = reachability.get("is_reachable", False)
    confidence = float(reachability.get("confidence", 0.0))
    base["stage2_result"] = reachability

    if not is_reachable:
        base["verdict"] = "NOT_REACHABLE"
        base["justification"] = (
            f"El paquete '{finding.effective_purl}' está instalado como dependencia "
            f"pero nunca es importado en el código fuente del proyecto. "
            f"La vulnerabilidad {finding.cve_id} no es explotable en este contexto."
        )
        # Nota: no escribimos en DT aquí porque no tenemos component_uuid ni vuln_uuid
        # (esos vienen de DT, no del reporte de dep-check).
        # El análisis background (zeronoise-background job) lo escribirá una vez
        # que DT esté actualizado con el SBOM del commit actual.
        return base

    # REACHABLE pero confianza baja → Stage 3 gate
    if confidence < stage3_threshold:
        base["verdict"] = "REACHABLE"
        base["justification"] = (
            f"Paquete alcanzable (confianza {confidence:.0%}) pero por debajo "
            f"del umbral Stage 3 ({stage3_threshold:.0%}). "
            f"Requiere revisión humana para determinar explotabilidad."
        )
        base["requires_human_review"] = True
        return base

    # --- Stage 3: LLM (consume tokens) ---
    base["stage3_used"] = True
    try:
        context = await prepare_stage3_context(
            package_name=finding.effective_purl,
            vulnerability_id=finding.cve_id,
            # dep-check no provee entry points específicos
            # Stage 3 hará un análisis general de uso del paquete
            vulnerable_functions=[],
            project_path=project_path,
        )

        verdict_result = await generate_finding_verdict(
            package_name=finding.effective_purl,
            vulnerability_id=finding.cve_id,
            severity=finding.severity,
            description=finding.description,
            stage2_result=reachability,
            stage3_context=context,
            dry_run=dry_run,
        )

        base["verdict"] = verdict_result.get("verdict", "UNKNOWN")
        base["justification"] = verdict_result.get("justification", "")
        base["stage3_analysis"] = verdict_result.get("analysis", {})

    except Exception as e:
        base["verdict"] = "REACHABLE"
        base["justification"] = (
            f"Stage 3 falló para {finding.cve_id}: {e}. "
            f"El paquete es alcanzable — requiere revisión humana."
        )
        base["requires_human_review"] = True

    return base
```

---

## 2. Registro en `server.py`

Agregar **exactamente estas dos líneas** en `server.py`, junto a los demás registros de tools. No modificar nada más:

```python
# En la sección de imports, junto a los otros tools:
from zeronoise.tools.depcheck_gate import analyze_depcheck_report

# En la sección de registros mcp.tool(), junto a los otros:
mcp.tool()(analyze_depcheck_report)
```

---

## 3. POC Script — `scripts/poc_depcheck.py`

Este script permite probar el flujo completo desde la terminal, igual que los POCs existentes de Stage 1/2/3.

```python
"""
poc_depcheck.py — POC: flujo completo dep-check → Stage 2 → Stage 3.

Punto de prueba sin pipeline de CI/CD. Replica lo que hará el fast-gate
cuando el pipeline entregue el reporte de dep-check a ZeroNoise.

Uso:
    # Análisis básico (dry-run, threshold 7.0)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/dependency-check-report.json \\
        --project-path /ruta/al/codigo/fuente

    # Con threshold personalizado
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --cvss-threshold 9.0

    # Aplicar verdicts en DT (escritura real — requiere project-uuid)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --apply

    # Solo diagnóstico del reporte (sin correr stages)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --diagnose-only
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path


async def run_diagnose_only(report_path: str, threshold: float) -> None:
    """Solo imprime el diagnóstico del ingester sin correr Stage 2/3."""
    from zeronoise.clients.depcheck_ingester import DepCheckIngester

    ingester = DepCheckIngester(report_path)
    meta = ingester.get_report_metadata()
    all_findings = ingester.load()
    blockers = ingester.filter_by_cvss(all_findings, threshold)

    print(f"\n{'='*60}")
    print(f"  DIAGNÓSTICO — {meta['project_name']}")
    print(f"  Scanner: {meta['scanner_version']} | Schema: {meta['schema_version']}")
    print(f"  Fecha:   {meta['report_date']}")
    print(f"{'='*60}")
    print(f"  Total deps:       {meta['total_dependencies']}")
    print(f"  Con vulns:        {meta['dependencies_with_vulns']}")
    print(f"  CVEs únicos:      {len(all_findings)}")
    print(f"  Gate blockers     ")
    print(f"  (CVSS >= {threshold}):  {len(blockers)}")
    print()

    for f in all_findings:
        is_blocker = f in blockers
        marker = "🔴 BLOCKER" if is_blocker else "⚪ no blocker"
        score_str = f"{f.cvss.score} ({f.cvss.source.value})" if f.cvss else "sin score"
        purl_str = f.effective_purl or "NO PURL"
        conf_str = f.primary_package.purl_confidence.value if f.primary_package else "N/A"
        n_jars = len(f.affected_packages)

        print(f"  [{marker}] {f.cve_id}  CVSS: {score_str}  {f.severity}")
        print(f"    PURL ({conf_str}): {purl_str}")
        print(f"    JARs afectados: {n_jars}")
        for p in f.affected_packages:
            shaded = " [SHADED]" if p.shadowed_dependency else ""
            mismatch = " [CPE_MISMATCH]" if p.cpe_version_mismatch else ""
            print(f"      · {p.file_name}{shaded}{mismatch}")
        if f.identification_issues:
            print(f"    ⚠ Issues:")
            for issue in f.identification_issues:
                print(f"      · {issue}")
        if f.requires_human_review:
            print(f"    👤 REQUIERE REVISIÓN HUMANA")
        print()


async def run_full_analysis(
    report_path: str,
    project_path: str,
    threshold: float,
    apply: bool,
) -> None:
    """Ejecuta el flujo completo: dep-check → Stage 2 → Stage 3."""
    from fastmcp import Client
    from zeronoise.server import mcp

    print(f"\n🔍 Iniciando análisis ZeroNoise...")
    print(f"   Reporte:  {report_path}")
    print(f"   Proyecto: {project_path}")
    print(f"   Umbral:   CVSS >= {threshold}")
    print(f"   Modo:     {'APPLY (escribe en DT)' if apply else 'DRY-RUN'}")
    print()

    async with Client(mcp) as client:
        result = await client.call_tool(
            "analyze_depcheck_report",
            {
                "report_path": report_path,
                "project_path": project_path,
                "cvss_threshold": threshold,
                "dry_run": not apply,
            },
        )

    # Parsear resultado
    raw = result[0].text if result else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"❌ Error parseando resultado: {raw}")
        sys.exit(1)

    # Imprimir resumen
    decision = data.get("pipeline_decision", "UNKNOWN")
    summary = data.get("summary", {})

    print(f"{'='*60}")
    print(f"  RESULTADO ZERONOISE")
    print(f"{'='*60}")
    decision_icon = "✅ PROMOTE" if decision == "PROMOTE" else "❌ BLOCK"
    print(f"  Pipeline decision: {decision_icon}")
    print()
    print(f"  Gate blockers encontrados: {summary.get('gate_blockers_found', 0)}")
    print(f"  NOT_REACHABLE (0 tokens):  {summary.get('not_reachable', 0)}")
    print(f"  Analizados por LLM:        {summary.get('reachable', 0)}")
    print(f"  EXPLOITABLE/LIKELY:        {summary.get('exploitable', 0)}")
    print(f"  UNKNOWN (revisión humana): {summary.get('unknown', 0)}")
    print(f"  {summary.get('tokens_used', '')}")
    print()

    # Detalle por CVE
    print("  Verdicts por CVE:")
    for v in data.get("verdicts", []):
        verdict = v.get("verdict", "UNKNOWN")
        icons = {
            "NOT_REACHABLE": "🟢",
            "FALSE_POSITIVE": "🟢",
            "REACHABLE": "🟡",
            "LIKELY_EXPLOITABLE": "🔴",
            "EXPLOITABLE": "🔴",
            "UNKNOWN": "⚪",
        }
        icon = icons.get(verdict, "⚪")
        print(f"  {icon} {v.get('cve_id')} → {verdict}")
        print(f"     Paquete: {v.get('package')} (PURL {v.get('purl_confidence')})")
        print(f"     {v.get('justification', '')[:200]}")
        if v.get("requires_human_review"):
            print(f"     👤 Requiere revisión humana")
        if v.get("identification_issues"):
            for issue in v["identification_issues"]:
                print(f"     ⚠ {issue}")
        print()

    # Razón de la decisión
    if decision == "BLOCK":
        print(f"  ❌ BLOCK reason: {data.get('block_reason')}")
    else:
        print(f"  ✅ PROMOTE reason: {data.get('promote_reason')}")

    # Guardar resultado JSON
    output_path = Path("depcheck_gate_result.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n  Resultado completo guardado en: {output_path}")

    # Exit code para uso en CI
    sys.exit(0 if decision == "PROMOTE" else 1)


def main():
    parser = argparse.ArgumentParser(
        description="ZeroNoise — Análisis de reporte OWASP Dependency-Check"
    )
    parser.add_argument(
        "--report", required=True,
        help="Ruta al reporte JSON de dep-check"
    )
    parser.add_argument(
        "--project-path", required=True,
        help="Ruta al código fuente del proyecto"
    )
    parser.add_argument(
        "--cvss-threshold", type=float, default=None,
        help="Umbral CVSS (default: GATE_CVSS_THRESHOLD del .env o 7.0)"
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Escribir verdicts en DT (default: dry-run)"
    )
    parser.add_argument(
        "--diagnose-only", action="store_true",
        help="Solo diagnosticar el reporte sin correr Stage 2/3"
    )
    args = parser.parse_args()

    # Resolver threshold
    threshold = args.cvss_threshold
    if threshold is None:
        try:
            from zeronoise.config import get_settings
            threshold = get_settings().gate_cvss_threshold
        except Exception:
            threshold = 7.0

    if args.diagnose_only:
        asyncio.run(run_diagnose_only(args.report, threshold))
    else:
        asyncio.run(run_full_analysis(
            report_path=args.report,
            project_path=args.project_path,
            threshold=threshold,
            apply=args.apply,
        ))


if __name__ == "__main__":
    main()
```

---

## 4. Agregar `GATE_CVSS_THRESHOLD` a `config.py`

En `config.py`, en la clase `Settings` de pydantic-settings, agregar el campo:

```python
# Agregar junto a stage3_confidence_threshold:
gate_cvss_threshold: float = 7.0
```

El `.env.example` ya tiene `GATE_CVSS_THRESHOLD=7.0` documentado.

---

## 5. Actualizar `CLAUDE.md` — sección Commands

Agregar estos comandos a la sección `## Commands`:

```bash
# POC Dep-Check Gate — solo diagnóstico del reporte (sin correr stages)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --diagnose-only

# POC Dep-Check Gate — análisis completo (dry-run)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente

# POC Dep-Check Gate — con threshold personalizado
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --cvss-threshold 9.0

# POC Dep-Check Gate — aplicar verdicts en DT (escritura real)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --apply
```

---

## 6. Cómo probar paso a paso

### Paso 1 — Diagnóstico del reporte (sin código fuente, sin DT)

Verifica que el ingester lee correctamente el reporte y clasifica los findings:

```bash
uv run python scripts/poc_depcheck.py \
    --report /ruta/a/dependency-check-report.json \
    --project-path /ruta/al/proyecto \
    --diagnose-only
```

**Output esperado:**
```
  CVEs únicos:     5
  Gate blockers    
  (CVSS >= 7.0):   3

  [🔴 BLOCKER] CVE-2026-33871  CVSS: 7.5 (v3)  HIGH
    PURL (HIGH): pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final
    JARs afectados: 6
      · netty-resolver-dns-4.1.128.Final.jar
      · grpc-netty-shaded-1.80.0.jar [SHADED]
      · reactor-netty-1.2.9.jar [CPE_MISMATCH]
    ...
```

Si el output es correcto, el ingester funciona.

---

### Paso 2 — Stage 2 solo (sin LLM, sin DT)

Verifica que Stage 2 puede buscar los imports en el código fuente:

```bash
uv run python scripts/poc_stage2.py \
    --project-path /ruta/al/codigo/fuente \
    --package "pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final"
```

Esto responde la pregunta: ¿el código fuente importa `io.netty`?

**Si responde NOT_REACHABLE:** el fast-gate completo también dirá PROMOTE para ese CVE.
**Si responde REACHABLE:** Stage 3 se activará cuando corras el flujo completo.

---

### Paso 3 — Flujo completo dry-run

Con el reporte real y el código fuente del proyecto:

```bash
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente
```

Este comando replica exactamente lo que hará el fast-gate en el pipeline.

---

### Paso 4 — Verificar el resultado

El script guarda `depcheck_gate_result.json` en el directorio actual. Revisar:
- `pipeline_decision`: PROMOTE o BLOCK
- `summary.not_reachable`: cuántos CVEs se resolvieron sin tokens
- `summary.tokens_used`: cuántos findings llegaron a Stage 3
- `verdicts[].justification`: la explicación técnica por CVE

---

## Diferencia con el flujo DT (prompt directo)

| Aspecto | Flujo DT (existente) | Flujo dep-check (nuevo) |
|---|---|---|
| **Activación** | Prompt: "analiza proyecto UUID X" | Archivo: `dependency-check-report.json` |
| **Fuente de findings** | API de Dependency-Track | Reporte JSON local |
| **PURLs** | Siempre correctos (del SBOM) | Parciales — ver `purl_confidence` |
| **UUIDs de componente** | Disponibles → escribe en DT | No disponibles → no escribe en DT |
| **Escritura en DT** | Sí, si `--apply` | No (los UUIDs vienen post SEND-SBOM) |
| **Momento de uso** | Post SEND-SBOM (background) | Pre SEND-SBOM (fast-gate) |
| **Deduplicación** | Por finding de DT | Por CVE (N JARs = 1 análisis) |

**La escritura en DT siempre la hace el flujo background** (post SEND-SBOM) porque
es ahí donde DT tiene los UUIDs de componente correctos del SBOM actual.
El fast-gate solo decide PROMOTE/BLOCK — el audit trail en DT lo completa el background job.

---

## Lo que NO tocar

- `tools/reachability.py` — se invoca tal cual, sin modificar su firma
- `tools/stage3_context.py` — ídem
- `tools/decision.py` — ídem  
- `models/vulnerability.py` — `DepCheckFinding` es paralelo, no reemplaza `Finding`
- `server.py` — solo agregar las dos líneas del paso 2, nada más
- `dry_run=True` por defecto — no cambiar
