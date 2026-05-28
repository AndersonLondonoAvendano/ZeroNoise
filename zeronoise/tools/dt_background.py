"""
dt_background.py — MCP tool: analyze_project_vulnerabilities

Frente DT: pipeline Stage 1 → Stage 0 → Stage 2 → Stage 3 para proyectos
en Dependency-Track. Equivalente a analyze_depcheck_report pero consumiendo
findings desde la API de DT en lugar del reporte JSON de dep-check.

Unifica el frente DT con el frente dep-check: ambos usan run_stage0() para
verificar la versión efectiva en el árbol de dependencias y el advisory del CVE
antes del análisis de alcanzabilidad.

Registro en server.py:
    from zeronoise.tools.dt_background import analyze_project_vulnerabilities
    mcp.tool()(analyze_project_vulnerabilities)
"""
from __future__ import annotations

from zeronoise.audit import audit_tool, safe_tool
from zeronoise.clients.dependency_track import dt_client
from zeronoise.config import get_settings
from zeronoise.tools._validators import _validate_project_path, _validate_uuid


_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNASSIGNED": 0,
}


def _parse_purl(purl: str) -> tuple[str, str]:
    """
    Extrae artifact_name y version de un PURL Maven.
    pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final
    → ("netty-resolver-dns", "4.1.128.Final")
    """
    if not purl:
        return "", ""
    try:
        parts = purl.split("/")
        artifact_at_version = parts[-1]
        if "@" in artifact_at_version:
            artifact, version = artifact_at_version.split("@", 1)
            return artifact, version
        return artifact_at_version, ""
    except Exception:
        return "", ""


@safe_tool
@audit_tool(side_effects="conditional")
async def analyze_project_vulnerabilities(
    project_uuid: str,
    project_path: str,
    severity_filter: str = "HIGH",
    dry_run: bool = True,
) -> dict:
    """
    Analiza las vulnerabilidades de un proyecto en Dependency-Track usando el
    pipeline completo: Stage 0 → Stage 2 → Stage 3.

    Flujo:
      1. Stage 1: Obtiene findings actionables de DT filtrados por severidad
      2. Stage 0: Verifica la versión real en árbol de dependencias / artefacto compilado
      3. Stage 2: Análisis de alcanzabilidad (0 tokens)
      4. Stage 3: Contexto heurístico + contexto del proyecto (0 tokens LLM)
      5. Genera VEX report con todos los verdicts

    Args:
        project_uuid:     UUID del proyecto en Dependency-Track.
        project_path:     Ruta absoluta al código fuente del proyecto.
        severity_filter:  Severidad mínima a analizar.
                          CRITICAL → solo CRITICAL
                          HIGH     → HIGH y CRITICAL (default)
                          MEDIUM   → MEDIUM, HIGH y CRITICAL
                          ALL      → todos
        dry_run:          Si True, no escribe verdicts en DT. Default: True.

    Returns:
        {
          "pipeline_decision": "PROMOTE" | "BLOCK",
          "summary": {
            "project": str,
            "total_actionable": int,
            "filtered_by_severity": int,
            "not_reachable": int,
            "reachable": int,
            "exploitable": int,
            "false_positive": int,
            "unknown": int,
            "tokens_used": str,
          },
          "verdicts": [...],
          "vex_report": {...},
          "block_reason": str | null,
          "promote_reason": str | null,
        }

    Contrato MCP:
        read_only: false (escribe en DT si dry_run=False)
        side_effects: conditional
        requires_confirmation: false
        expected_cost: low (Stage 3 heurístico, sin llamadas LLM)
    """
    settings = get_settings()

    _validate_uuid(project_uuid, "project_uuid")
    _validate_project_path(project_path)

    # Stage 1: Obtener findings de DT
    project_findings = await dt_client.get_project_findings(project_uuid)
    actionable = project_findings.actionable

    # Filtrar por severidad
    sf_upper = severity_filter.upper()
    min_rank = 0 if sf_upper == "ALL" else _SEVERITY_RANK.get(sf_upper, 3)
    to_analyze = [
        f for f in actionable
        if _SEVERITY_RANK.get(str(f.vulnerability.severity).upper(), 0) >= min_rank
    ]

    if not to_analyze:
        return {
            "pipeline_decision": "PROMOTE",
            "summary": {
                "project": project_findings.project.name,
                "total_actionable": len(actionable),
                "filtered_by_severity": 0,
                "not_reachable": 0,
                "reachable": 0,
                "exploitable": 0,
                "false_positive": 0,
                "unknown": 0,
                "tokens_used": "Stage 3 no ejecutado — no hay findings para analizar",
            },
            "verdicts": [],
            "vex_report": None,
            "block_reason": None,
            "promote_reason": (
                f"No se encontraron findings con severidad >= {severity_filter} "
                f"para el proyecto '{project_findings.project.name}'."
            ),
            "dry_run": dry_run,
        }

    # Imports tardíos para evitar circularidad
    from zeronoise.analyzers.project_context_reader import ProjectContextReader
    from zeronoise.tools.decision import generate_finding_verdict, generate_vex_report
    from zeronoise.tools.depcheck_gate import run_stage0
    from zeronoise.tools.reachability import analyze_package_reachability
    from zeronoise.tools.stage3_context import prepare_stage3_context

    # Leer contexto del proyecto UNA SOLA VEZ
    _proj_ctx = ProjectContextReader(project_path).read()
    _proj_ctx_str = _proj_ctx.to_llm_context()

    verdicts = []
    stage3_count = 0
    block_reasons = []

    for finding in to_analyze:
        entry = await _analyze_dt_finding(
            finding=finding,
            project_path=project_path,
            project_uuid=project_uuid,
            stage3_threshold=settings.stage3_confidence_threshold,
            analyze_package_reachability=analyze_package_reachability,
            prepare_stage3_context=prepare_stage3_context,
            generate_finding_verdict=generate_finding_verdict,
            proj_ctx_str=_proj_ctx_str,
            proj_ctx=_proj_ctx,
            dry_run=dry_run,
            run_stage0=run_stage0,
        )
        verdicts.append(entry)

        if entry.get("stage3_used"):
            stage3_count += 1

        if entry["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
            cve_id = finding.vulnerability.vuln_id
            pkg = finding.component.name
            block_reasons.append(
                f"{cve_id} ({pkg}): {entry['justification'][:200]}"
            )

    # Generar VEX (best-effort)
    vex = None
    try:
        vex_findings = [
            {
                "vuln_id": v["cve_id"],
                "purl": v.get("purl") or f"dt:{v['cve_id']}",
                "component": v["package"],
                "verdict": v["verdict"],
                "justification": (
                    "FEATURE_NOT_USED"
                    if v["verdict"] in ("FALSE_POSITIVE", "NOT_REACHABLE")
                    else "NOT_SET"
                ),
                "analysis_details": v.get("justification", ""),
                "confidence": v.get("confidence", 0.0),
                "evidence": v.get("evidence", []),
            }
            for v in verdicts
        ]
        vex = await generate_vex_report(
            project_name=project_findings.project.name,
            project_version=project_findings.project.version or "unknown",
            findings=vex_findings,
        )
    except Exception:
        pass

    pipeline_decision = "BLOCK" if block_reasons else "PROMOTE"

    counts = {
        "not_reachable": sum(1 for v in verdicts if v["verdict"] == "NOT_REACHABLE"),
        "reachable": sum(1 for v in verdicts if v["verdict"] == "REACHABLE"),
        "exploitable": sum(
            1 for v in verdicts if v["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE")
        ),
        "false_positive": sum(1 for v in verdicts if v["verdict"] == "FALSE_POSITIVE"),
        "unknown": sum(1 for v in verdicts if v["verdict"] == "UNKNOWN"),
    }

    return {
        "pipeline_decision": pipeline_decision,
        "summary": {
            "project": project_findings.project.name,
            "total_actionable": len(actionable),
            "filtered_by_severity": len(to_analyze),
            **counts,
            "tokens_used": (
                f"Stage 3 ejecutado para {stage3_count}/{len(to_analyze)} findings"
            ),
        },
        "verdicts": verdicts,
        "vex_report": vex,
        "block_reason": " | ".join(block_reasons) if block_reasons else None,
        "promote_reason": (
            "Todos los findings son NOT_REACHABLE o FALSE_POSITIVE"
            if pipeline_decision == "PROMOTE" else None
        ),
        "dry_run": dry_run,
    }


async def _analyze_dt_finding(
    finding,
    project_path: str,
    project_uuid: str,
    stage3_threshold: float,
    analyze_package_reachability,
    prepare_stage3_context,
    generate_finding_verdict,
    proj_ctx_str: str,
    proj_ctx,
    dry_run: bool,
    run_stage0,
) -> dict:
    """Analiza un único Finding de DT. Retorna el dict de veredicto."""

    cve_id = finding.vulnerability.vuln_id
    purl = finding.component.purl or ""
    artifact_name, reported_version = _parse_purl(purl)
    if not artifact_name:
        artifact_name = finding.component.name or ""
    if not reported_version:
        reported_version = finding.component.version or ""

    entry: dict = {
        "cve_id": cve_id,
        "package": finding.component.name,
        "version": finding.component.version,
        "purl": purl,
        "severity": str(finding.vulnerability.severity),
        "component_uuid": finding.component.uuid,
        "vulnerability_uuid": finding.vulnerability.uuid,
        "finding_id": finding.finding_id,
        "verdict": "UNKNOWN",
        "justification": "",
        "confidence": 0.0,
        "evidence": [],
        "stage3_used": False,
        "requires_human_review": False,
    }

    # Fix 4: Obtener vulnerable_software desde DT API (best-effort)
    _vulnerable_software: list = []
    _description = finding.vulnerability.description or ""
    try:
        vuln_detail = await dt_client.get_vulnerability(
            finding.vulnerability.source,
            finding.vulnerability.vuln_id,
        )
        _vulnerable_software = vuln_detail.get("affectedVersionRanges", [])
        if not _vulnerable_software:
            _vulnerable_software = vuln_detail.get("versions", [])
        if not _description and vuln_detail.get("description"):
            _description = vuln_detail["description"]
    except Exception:
        pass

    # Stage 0: Verificación de versión real
    _stage0 = await run_stage0(
        artifact_name=artifact_name,
        reported_version=reported_version,
        cve_id=cve_id,
        vulnerable_software=_vulnerable_software,
        description=_description,
        cwes=[],
        project_path=project_path,
    )

    if _stage0["version_verification"]:
        entry["version_verification"] = _stage0["version_verification"]

    if _stage0["skip_stage2"]:
        entry["verdict"] = _stage0["verdict"]
        entry["justification"] = _stage0["justification"]
        entry["requires_human_review"] = _stage0.get("requires_human_review", False)
        return entry

    if _stage0["version_is_vulnerable"]:
        entry["version_note"] = _stage0["justification"]
        entry["version_is_vulnerable"] = True
    elif _stage0["justification"]:
        entry["version_note"] = _stage0["justification"]

    # Stage 2: Alcanzabilidad (0 tokens)
    pkg_id = purl if purl else f"pkg:generic/{artifact_name}@{reported_version}"
    try:
        reachability = await analyze_package_reachability(
            project_path=project_path,
            package_name=pkg_id,
        )
    except Exception as e:
        entry["verdict"] = "UNKNOWN"
        entry["justification"] = f"Error en Stage 2 para {pkg_id}: {e}"
        return entry

    if isinstance(reachability, dict) and reachability.get("error"):
        entry["verdict"] = "UNKNOWN"
        entry["justification"] = (
            f"Stage 2 falló para {pkg_id}: "
            f"{reachability.get('message', reachability.get('error'))}"
        )
        return entry

    is_reachable = reachability.get("is_reachable", False)
    confidence = float(reachability.get("confidence", 0.0))
    evidence = reachability.get("evidence", [])

    entry["stage2_result"] = reachability
    entry["confidence"] = confidence
    entry["evidence"] = evidence

    if not is_reachable:
        entry["verdict"] = "NOT_REACHABLE"
        entry["justification"] = (
            f"El paquete '{pkg_id}' está instalado como dependencia "
            f"pero nunca es importado en el código fuente del proyecto. "
            f"La vulnerabilidad {cve_id} no es explotable en este contexto."
        )
        if not dry_run:
            from zeronoise.tools.reachability import _can_overwrite
            current = await dt_client.get_analysis(
                project_uuid=project_uuid,
                component_uuid=finding.component.uuid,
                vulnerability_uuid=finding.vulnerability.uuid,
            )
            current_state = current.get("analysisState", "NOT_SET")
            if _can_overwrite(current_state, "NOT_AFFECTED"):
                await dt_client.update_analysis(
                    project_uuid=project_uuid,
                    component_uuid=finding.component.uuid,
                    vulnerability_uuid=finding.vulnerability.uuid,
                    state="NOT_AFFECTED",
                    justification="CODE_NOT_REACHABLE",
                    details=entry["justification"],
                )
        return entry

    if confidence < stage3_threshold:
        entry["verdict"] = "REACHABLE"
        entry["justification"] = (
            f"Paquete alcanzable (confianza {confidence:.0%}) pero por debajo "
            f"del umbral Stage 3 ({stage3_threshold:.0%}). "
            f"Requiere revisión humana para determinar explotabilidad."
        )
        entry["requires_human_review"] = True
        return entry

    # Stage 3: Contexto heurístico con contexto del proyecto (0 tokens LLM)
    entry["stage3_used"] = True
    try:
        context = await prepare_stage3_context(
            project_path=project_path,
            package_name=pkg_id,
            vulnerability_id=cve_id,
            severity=str(finding.vulnerability.severity),
            vulnerability_description=_description,
            vulnerable_functions=[
                vf.function_name for vf in finding.vulnerability.vulnerable_functions
            ],
            cvss=finding.vulnerability.cvss_v3_score,
        )

        if isinstance(context, dict) and context.get("error"):
            raise RuntimeError(context.get("message", context.get("error")))

        # Fix 3: Enriquecer con contexto del proyecto
        if isinstance(context, dict):
            context["project_context"] = proj_ctx_str
            if proj_ctx.spring_boot_version:
                context["spring_boot_version"] = proj_ctx.spring_boot_version
            if proj_ctx.declared_boms:
                context["declared_boms"] = proj_ctx.declared_boms
            if proj_ctx.excluded_modules:
                context["excluded_modules"] = proj_ctx.excluded_modules
            if entry.get("version_note"):
                context["version_verification_note"] = entry["version_note"]
            if _stage0["real_version"]:
                context["real_version"] = _stage0["real_version"]

        risk_signal = (
            context.get("pre_analysis_signals", {}).get("risk_signal", "LOW")
            if isinstance(context, dict) else "LOW"
        )
        heuristic_verdict = (
            "LIKELY_EXPLOITABLE" if risk_signal == "HIGH" else "REACHABLE"
        )

        annotated_evidence = [
            {**e, "reason": f"Paquete importado — señal de riesgo: {risk_signal}"}
            for e in evidence
        ]

        verdict_record = await generate_finding_verdict(
            finding_id=finding.finding_id,
            verdict=heuristic_verdict,
            justification="NOT_SET",
            confidence=confidence,
            evidence=annotated_evidence,
            analysis_details=(
                f"[ZeroNoise DT Stage 3] Señal de riesgo: {risk_signal}. "
                f"Contexto de Stage 3 ensamblado — análisis LLM completo pendiente. "
                f"IMPORTANTE: Todas las justificaciones deben estar en español."
            ),
        )

        final_verdict = verdict_record.get("verdict", heuristic_verdict)
        entry["verdict"] = final_verdict
        entry["justification"] = (
            f"Paquete '{pkg_id}' es alcanzable en el código fuente. "
            f"Señal de riesgo pre-análisis: {risk_signal}. "
            f"{'BLOQUEO preventivo hasta análisis LLM completo.' if final_verdict == 'LIKELY_EXPLOITABLE' else 'Requiere análisis LLM completo para confirmar explotabilidad.'}"
        )
        entry["stage3_context"] = context
        entry["stage3_analysis"] = verdict_record

    except Exception as e:
        entry["verdict"] = "REACHABLE"
        entry["justification"] = (
            f"Stage 3 falló para {cve_id}: {e}. "
            f"El paquete es alcanzable — requiere revisión humana."
        )
        entry["requires_human_review"] = True

    return entry
