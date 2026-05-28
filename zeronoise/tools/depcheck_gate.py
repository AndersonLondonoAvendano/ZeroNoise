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

from pathlib import Path
from typing import Optional

from zeronoise.audit import audit_tool, safe_tool
from zeronoise.clients.depcheck_ingester import DepCheckIngester
from zeronoise.config import get_settings
from zeronoise.models.depcheck_finding import DepCheckFinding


# Maps a verdict to the closest AnalysisJustification value for VEX generation.
_VERDICT_TO_JUSTIFICATION: dict[str, str] = {
    "NOT_REACHABLE": "CODE_NOT_REACHABLE",
    "FALSE_POSITIVE": "FEATURE_NOT_USED",
    "NOT_APPLICABLE": "CODE_NOT_REACHABLE",
}


def _vex_justification(verdict: str) -> str:
    return _VERDICT_TO_JUSTIFICATION.get(verdict, "NOT_SET")


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
      1. Lee el reporte y filtra findings con CVSS >= cvss_threshold (Stage 0)
      2. Para cada finding: Stage 2 (reachability, 0 tokens)
      3. Solo si REACHABLE + confidence >= threshold: Stage 3 (context heurístico, 0 tokens)
      4. Genera VEX report con todos los verdicts
      5. Retorna pipeline_decision: PROMOTE | BLOCK

    Args:
        report_path:     Ruta absoluta al reporte JSON de dep-check.
                         En CI: el artefacto generado por dependency_check.
        project_path:    Ruta absoluta al código fuente del proyecto.
                         En CI: $CI_PROJECT_DIR o $GITHUB_WORKSPACE
        cvss_threshold:  CVSS mínimo para considerar gate blocker.
                         Default: GATE_CVSS_THRESHOLD del .env (7.0)
        dry_run:         Si True, no escribe verdicts en DT. Default: True.

    Returns:
        {
          "pipeline_decision": "PROMOTE" | "BLOCK",
          "summary": {
            "gate_blockers_found": int,
            "not_reachable": int,       <- resueltos automáticamente (0 tokens)
            "reachable": int,           <- alcanzables, pendientes de análisis LLM
            "exploitable": int,         <- razón del BLOCK si aplica
            "unknown": int,             <- requieren revisión humana
            "tokens_used": str
          },
          "verdicts": [ ... ],          <- detalle por CVE
          "vex_report": { ... },        <- OpenVEX completo
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
    threshold = cvss_threshold if cvss_threshold is not None else settings.gate_cvss_threshold

    # --- Validaciones de entrada ---
    report_file = Path(report_path)
    if not report_file.exists():
        return {
            "error": "validation_error",
            "message": f"Reporte no encontrado: {report_path}",
        }
    if report_file.suffix != ".json":
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

    # Imports tardíos: evitar circularidad y solo cargar si hay blockers
    from zeronoise.tools.decision import generate_vex_report
    from zeronoise.tools.reachability import analyze_package_reachability
    from zeronoise.tools.stage3_context import prepare_stage3_context
    from zeronoise.tools.decision import generate_finding_verdict

    # Leer contexto del proyecto UNA SOLA VEZ para todos los findings
    import logging
    from zeronoise.analyzers.project_context_reader import ProjectContextReader

    _project_context = ProjectContextReader(project_path).read()
    _context_summary = _project_context.to_llm_context()

    _log = logging.getLogger("zeronoise.gate")
    _log.info(
        f"Contexto del proyecto: archivos leídos={_project_context.files_found}, "
        f"Spring Boot={_project_context.spring_boot_version}, "
        f"Java={_project_context.java_version}, "
        f"BOMs={_project_context.declared_boms}, "
        f"Exclusiones={_project_context.excluded_modules}"
    )

    verdicts = []
    stage3_count = 0
    block_reasons = []

    for finding in gate_blockers:
        verdict_entry = await _analyze_finding(
            finding=finding,
            project_path=project_path,
            stage3_threshold=settings.stage3_confidence_threshold,
            analyze_package_reachability=analyze_package_reachability,
            prepare_stage3_context=prepare_stage3_context,
            generate_finding_verdict=generate_finding_verdict,
            project_context_summary=_context_summary,
            project_context=_project_context,
        )
        verdicts.append(verdict_entry)

        if verdict_entry["stage3_used"]:
            stage3_count += 1

        if verdict_entry["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE"):
            pkg_name = (
                finding.primary_package.artifact_name
                if finding.primary_package else "unknown"
            )
            block_reasons.append(
                f"{finding.cve_id} ({pkg_name}): "
                f"{verdict_entry['justification'][:200]}"
            )

    # --- Generar VEX (best-effort) ---
    vex = None
    try:
        vex_findings = [
            {
                "vuln_id": v["cve_id"],
                "purl": v["purl"] or f"depcheck:{v['cve_id']}",
                "component": v["package"],
                "verdict": v["verdict"],
                "justification": _vex_justification(v["verdict"]),
                "analysis_details": v.get("justification", ""),
                "confidence": v.get("confidence", 0.0),
                "evidence": v.get("evidence", []),
            }
            for v in verdicts
        ]
        vex = await generate_vex_report(
            project_name=report_meta.get("project_name", "unknown"),
            project_version="unknown",
            findings=vex_findings,
        )
    except Exception:
        pass

    # --- Decisión final ---
    pipeline_decision = "BLOCK" if block_reasons else "PROMOTE"

    counts = {
        "not_reachable": sum(1 for v in verdicts if v["verdict"] == "NOT_REACHABLE"),
        "reachable": sum(
            1 for v in verdicts if v["verdict"] in ("REACHABLE", "FALSE_POSITIVE")
        ),
        "exploitable": sum(
            1 for v in verdicts if v["verdict"] in ("EXPLOITABLE", "LIKELY_EXPLOITABLE")
        ),
        "unknown": sum(1 for v in verdicts if v["verdict"] == "UNKNOWN"),
    }

    return {
        "pipeline_decision": pipeline_decision,
        "summary": {
            "gate_blockers_found": len(gate_blockers),
            **counts,
            "tokens_used": (
                f"Stage 3 ejecutado para {stage3_count}/{len(gate_blockers)} findings"
            ),
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


def _check_version_against_advisory(
    cve_id: str,
    effective_version: str,
    artifact_name: str,
    vulnerable_software: list,
    description: str,
    reported_version: str = "",
) -> str:
    """
    Determina si la versión efectiva está en el rango vulnerable del CVE.

    Fuentes en orden de prioridad:
      1. vulnerable_software del reporte dep-check (rangos estructurados)
      2. Descripción textual del CVE (regex sobre patrones comunes)
      3. Heurística de versión: major version completamente diferente → wrapper mismatch

    Returns:
        "NOT_VULNERABLE"          — versión fuera del rango, determinado por datos
        "NOT_VULNERABLE_HEURISTIC"— versión fuera del rango, determinado por heurística
        "VULNERABLE"              — versión dentro del rango afectado
        "UNKNOWN"                 — sin datos suficientes (pasar a Stage 3)
    """
    if vulnerable_software:
        result = _compare_version_to_ranges(effective_version, vulnerable_software)
        if result != "UNKNOWN":
            return result

    result = _extract_range_from_description(effective_version, description)
    if result != "UNKNOWN":
        return result

    # Heurística: major version completamente diferente → wrapper mismatch
    # Ej: effective=4.1.132.Final vs reported=1.2.16 (reactor-netty wrapper)
    if reported_version:
        try:
            from packaging.version import Version
            import re as _re

            def _norm(v: str) -> str:
                clean = _re.sub(
                    r'[\.\-](RELEASE|Final|GA|SP\d+|RC\d+|M\d+|Alpha\d*|Beta\d*)$',
                    '', v.strip(), flags=_re.IGNORECASE
                )
                return _re.sub(r'\.(RELEASE|Final|GA)$', '', clean, flags=_re.IGNORECASE)

            eff = Version(_norm(effective_version))
            rep = Version(_norm(reported_version))
            if eff.major != rep.major and eff > rep:
                return "NOT_VULNERABLE_HEURISTIC"
        except Exception:
            pass

    return "UNKNOWN"


def _compare_version_to_ranges(version: str, ranges: list) -> str:
    """
    Compara una versión contra múltiples rangos.
    Retorna VULNERABLE si cae en CUALQUIER rango. NOT_VULNERABLE si no cae
    en ninguno y al menos un rango fue parseable.
    """
    try:
        from packaging.version import Version
        import re as _re

        def normalize(v: str) -> str:
            v = v.strip()
            # Remover qualifiers con punto: 3.1.3.RELEASE, 4.1.132.Final, 5.3.0.GA
            v = _re.sub(
                r'\.(?:RELEASE|Final|GA|SP\d+|RC\d+|M\d+|CR\d+|Alpha\d*|Beta\d*)$',
                '', v, flags=_re.IGNORECASE
            )
            # Remover qualifiers con guión: 3.1.3-RELEASE, 4.0.0-RC1, 1.0.0-beta.1
            v = _re.sub(
                r'-(?:RELEASE|Final|GA|SP\d+|RC\d+|M\d+|CR\d+|Alpha\d*|Beta\d*|SNAPSHOT).*$',
                '', v, flags=_re.IGNORECASE
            )
            # Remover cualquier qualifier residual sin separador
            v = _re.sub(r'(?:Final|RELEASE|GA)$', '', v, flags=_re.IGNORECASE)
            return v.strip('.-')

        effective = Version(normalize(version))
        parseable = 0

        for range_str in ranges:
            r = str(range_str).strip()
            try:
                if r.startswith("< "):
                    upper = Version(normalize(r[2:].strip()))
                    parseable += 1
                    if effective < upper:
                        return "VULNERABLE"
                elif r.startswith("<= "):
                    upper = Version(normalize(r[3:].strip()))
                    parseable += 1
                    if effective <= upper:
                        return "VULNERABLE"
                elif r.startswith("> ") and ", < " in r:
                    parts = r.split(", < ")
                    lower = Version(normalize(parts[0][2:].strip()))
                    upper = Version(normalize(parts[1].strip()))
                    parseable += 1
                    if lower < effective < upper:
                        return "VULNERABLE"
                elif r.startswith(">= ") and ", <= " in r:
                    parts = r.split(", <= ")
                    lower = Version(normalize(parts[0][3:].strip()))
                    upper = Version(normalize(parts[1].strip()))
                    parseable += 1
                    if lower <= effective <= upper:
                        return "VULNERABLE"
                elif r.startswith(">= ") and ", < " in r:
                    parts = r.split(", < ")
                    lower = Version(normalize(parts[0][3:].strip()))
                    upper = Version(normalize(parts[1].strip()))
                    parseable += 1
                    if lower <= effective < upper:
                        return "VULNERABLE"
            except Exception:
                pass

        if parseable > 0:
            return "NOT_VULNERABLE"
    except Exception:
        pass
    return "UNKNOWN"


def _extract_range_from_description(version: str, description: str) -> str:
    """Extrae el rango de versiones de la descripción del CVE con regex."""
    import re as _re

    patterns = [
        r'(?:before|prior to|earlier than)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'fixed (?:in|with|by)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'versions?\s+(?:before|prior to)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'upgrade to\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'update to\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'versions\s+before\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'([\d]+\.[\d.]+(?:\.\w+)?)\s+and\s+(?:earlier|prior)',
        r'up to (?:and including\s+)?([\d]+\.[\d.]+(?:\.\w+)?)',
        r'through\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'affects.*?through\s+([\d]+\.[\d.]+(?:\.\w+)?)',
    ]
    for pattern in patterns:
        match = _re.search(pattern, description, _re.IGNORECASE)
        if match:
            fix_version = match.group(1)
            if any(p in pattern for p in ['through', 'and earlier', 'up to']):
                return _compare_version_to_ranges(version, [f"<= {fix_version}"])
            else:
                return _compare_version_to_ranges(version, [f"< {fix_version}"])

    return "UNKNOWN"


async def run_stage0(
    artifact_name: str,
    reported_version: str,
    cve_id: str,
    vulnerable_software: list,
    description: str,
    cwes: list,
    project_path: str,
) -> dict:
    """
    Stage 0: Verificación de versión real antes de Stage 2.

    Reutilizable por ambos frentes (dep-check y DT).

    Returns:
        {
          "verdict": "FALSE_POSITIVE" | "VULNERABLE_IN_RUNTIME" | None,
          "justification": str,
          "real_version": str | None,
          "version_source": str,
          "resolution_note": str,
          "version_is_vulnerable": bool,
          "requires_human_review": bool,
          "skip_stage2": bool,
          "version_verification": dict | None,
        }
    """
    from zeronoise.analyzers.artifact_inspector import ArtifactInspector
    from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
    from zeronoise.models.artifact_finding import VersionVerdict

    result: dict = {
        "verdict": None,
        "justification": "",
        "real_version": None,
        "version_source": "unknown",
        "resolution_note": "",
        "version_is_vulnerable": False,
        "requires_human_review": False,
        "skip_stage2": False,
        "version_verification": None,
    }

    if not artifact_name or not reported_version:
        return result

    tree_parser = DependencyTreeParser(project_path)
    artifact_inspector = ArtifactInspector(project_path)

    effective_version, resolution_note = tree_parser.resolve_effective_version(
        artifact_name, reported_version
    )
    av = artifact_inspector.verify_version(artifact_name, reported_version)

    if effective_version:
        real_version = effective_version
        version_source = "dependency_tree"
    elif av and av.real_version:
        real_version = av.real_version
        version_source = "compiled_artifact"
        resolution_note = (
            f"Versión encontrada en el artefacto compilado: "
            f"{artifact_name}@{real_version}. "
            f"El árbol de dependencias no resolvió este artifact."
        )
    else:
        real_version = reported_version
        version_source = "depcheck_reported"
        resolution_note = (
            f"Usando versión reportada como referencia: "
            f"{artifact_name}@{real_version}."
        )

    result["real_version"] = real_version
    result["version_source"] = version_source
    result["resolution_note"] = resolution_note
    result["version_verification"] = {
        "reported_version": reported_version,
        "effective_version": real_version,
        "version_source": version_source,
        "resolution_note": resolution_note,
        "artifact_check": av.summary if av else "No verificado",
    }

    # CASO 1: NOT_FOUND en árbol Y artefacto → falso positivo del scanner
    av_nf = av and av.verdict == VersionVerdict.NOT_FOUND
    tree_nf = effective_version is None
    if av_nf and tree_nf:
        result["verdict"] = "FALSE_POSITIVE"
        result["justification"] = (
            f"'{artifact_name}' no está empaquetado en el artefacto final "
            f"ni en el árbol de dependencias runtime. "
            f"Falso positivo del scanner — paquete no presente en el classpath real."
        )
        result["skip_stage2"] = True
        return result

    # CASO 2: Cruzar versión con el advisory del CVE
    advisory_verdict = _check_version_against_advisory(
        cve_id=cve_id,
        effective_version=real_version,
        artifact_name=artifact_name,
        vulnerable_software=vulnerable_software,
        description=description,
        reported_version=reported_version,
    )

    if advisory_verdict in ("NOT_VULNERABLE", "NOT_VULNERABLE_HEURISTIC"):
        heuristic = advisory_verdict == "NOT_VULNERABLE_HEURISTIC"
        result["verdict"] = "FALSE_POSITIVE"
        result["justification"] = (
            f"La versión efectiva en runtime "
            f"({artifact_name}@{real_version}, fuente: {version_source}) "
            f"no está en el rango de versiones afectadas por {cve_id}. "
            f"{resolution_note}"
            + (" [Determinado por heurística de versión — verificar manualmente]"
               if heuristic else "")
        )
        result["requires_human_review"] = heuristic
        result["skip_stage2"] = True
        return result

    elif advisory_verdict == "VULNERABLE":
        result["version_is_vulnerable"] = True
        result["verdict"] = "VULNERABLE_IN_RUNTIME"
        result["justification"] = (
            f"ATENCIÓN: {artifact_name}@{real_version} "
            f"ESTÁ en el rango vulnerable de {cve_id}. "
            f"Fuente: {version_source}. "
            f"Continuar con análisis de alcanzabilidad."
        )

    else:
        # UNKNOWN → enriquecer nota de versión pero continuar
        result["justification"] = (
            f"Versión efectiva en runtime: {artifact_name}@{real_version} "
            f"(reportada: {reported_version}). "
            f"{resolution_note}"
        )

    return result


async def _analyze_finding(
    finding: DepCheckFinding,
    project_path: str,
    stage3_threshold: float,
    analyze_package_reachability,
    prepare_stage3_context,
    generate_finding_verdict,
    project_context_summary: str = "",
    project_context=None,
) -> dict:
    """Analiza un único DepCheckFinding. Retorna el dict de veredicto."""

    base: dict = {
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
        "confidence": 0.0,
        "evidence": [],
        "stage3_used": False,
    }

    # Stage 0: Verificacion de version real
    _artifact_name = (
        finding.primary_package.artifact_name
        if finding.primary_package else ""
    )
    _reported_version = (
        finding.primary_package.artifact_version
        if finding.primary_package else ""
    )

    _stage0 = await run_stage0(
        artifact_name=_artifact_name,
        reported_version=_reported_version,
        cve_id=finding.cve_id,
        vulnerable_software=getattr(finding, "vulnerable_software", []),
        description=finding.description,
        cwes=getattr(finding, "cwes", []),
        project_path=project_path,
    )

    _real_version = _stage0["real_version"] or _reported_version

    if _stage0["version_verification"]:
        base["version_verification"] = _stage0["version_verification"]

    if _stage0["skip_stage2"]:
        base["verdict"] = _stage0["verdict"]
        base["justification"] = _stage0["justification"]
        base["requires_human_review"] = _stage0.get("requires_human_review", False)
        return base

    if _stage0["version_is_vulnerable"]:
        base["version_note"] = _stage0["justification"]
        base["version_is_vulnerable"] = True
    elif _stage0["justification"]:
        base["version_note"] = _stage0["justification"]

    # Fin Stage 0

    # Sin PURL suficientemente confiable → Stage 2 no puede ejecutarse
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
            project_path=project_path,
            package_name=finding.effective_purl,
        )
    except Exception as e:
        base["verdict"] = "UNKNOWN"
        base["justification"] = (
            f"Error en Stage 2 para {finding.effective_purl}: {e}"
        )
        return base

    # Manejar error interno de @safe_tool
    if isinstance(reachability, dict) and reachability.get("error"):
        base["verdict"] = "UNKNOWN"
        base["justification"] = (
            f"Stage 2 falló para {finding.effective_purl}: "
            f"{reachability.get('message', reachability.get('error'))}"
        )
        return base

    is_reachable = reachability.get("is_reachable", False)
    confidence = float(reachability.get("confidence", 0.0))
    evidence = reachability.get("evidence", [])

    base["stage2_result"] = reachability
    base["confidence"] = confidence
    base["evidence"] = evidence

    if not is_reachable:
        base["verdict"] = "NOT_REACHABLE"
        base["justification"] = (
            f"El paquete '{finding.effective_purl}' está instalado como dependencia "
            f"pero nunca es importado en el código fuente del proyecto. "
            f"La vulnerabilidad {finding.cve_id} no es explotable en este contexto."
        )
        # Escalar si la versión en runtime es vulnerable (classpath risk)
        if base.get("version_is_vulnerable"):
            cwe_high_risk = {
                "CWE-502",  # Deserialization of Untrusted Data
                "CWE-77",   # Command Injection
                "CWE-78",   # OS Command Injection
                "CWE-94",   # Code Injection
                "CWE-611",  # XXE
                "CWE-918",  # SSRF
            }
            finding_cwes = set(getattr(finding, 'cwes', []))
            if finding_cwes & cwe_high_risk:
                base["verdict"] = "LIKELY_EXPLOITABLE"
                base["justification"] = (
                    f"{_artifact_name}@{_real_version} está empaquetado en el "
                    f"artefacto final en versión vulnerable para {finding.cve_id}. "
                    f"Aunque no hay imports directos en el código fuente, "
                    f"la vulnerabilidad ({', '.join(finding_cwes)}) puede ser "
                    f"explotable mediante el classpath runtime. "
                    f"Requiere revisión humana antes de continuar el pipeline."
                )
                base["requires_human_review"] = True
            else:
                base["verdict"] = "REACHABLE"
                base["justification"] = (
                    f"{_artifact_name}@{_real_version} está empaquetado en el "
                    f"artefacto final en versión vulnerable para {finding.cve_id}. "
                    f"No hay imports directos pero la librería está en el classpath. "
                    f"Evaluar si puede excluirse del build o actualizar la versión."
                )
                base["requires_human_review"] = True
        return base

    # REACHABLE pero confianza insuficiente para Stage 3
    if confidence < stage3_threshold:
        base["verdict"] = "REACHABLE"
        base["justification"] = (
            f"Paquete alcanzable (confianza {confidence:.0%}) pero por debajo "
            f"del umbral Stage 3 ({stage3_threshold:.0%}). "
            f"Requiere revisión humana para determinar explotabilidad."
        )
        base["requires_human_review"] = True
        return base

    # --- Stage 3: Análisis de contexto heurístico (0 tokens LLM) ---
    base["stage3_used"] = True
    try:
        context = await prepare_stage3_context(
            project_path=project_path,
            package_name=finding.effective_purl,
            vulnerability_id=finding.cve_id,
            severity=finding.severity,
            vulnerability_description=finding.description,
            vulnerable_functions=[],
            cvss=finding.cvss.score if finding.cvss else None,
        )

        # Manejar error de prepare_stage3_context
        if isinstance(context, dict) and context.get("error"):
            raise RuntimeError(context.get("message", context.get("error")))

        # Adjuntar verificación de versión al contexto para Stage 3
        _stage3_version_note = base.get("version_note", "")
        _stage3_real_version = base.get("version_verification", {}).get("effective_version")
        if _stage3_version_note and isinstance(context, dict):
            context["version_verification_note"] = _stage3_version_note
            if _stage3_real_version:
                context["real_version"] = _stage3_real_version

        # Enriquecer el context bundle con el contexto del proyecto
        if isinstance(context, dict):
            context["project_context"] = project_context_summary
            if project_context:
                if project_context.spring_boot_version:
                    context["spring_boot_version"] = project_context.spring_boot_version
                if project_context.declared_boms:
                    context["declared_boms"] = project_context.declared_boms
                if project_context.excluded_modules:
                    context["excluded_modules"] = project_context.excluded_modules

        # Determinar veredicto heurístico desde las señales pre-análisis
        risk_signal = (
            context.get("pre_analysis_signals", {}).get("risk_signal", "LOW")
        )
        heuristic_verdict = (
            "LIKELY_EXPLOITABLE" if risk_signal == "HIGH" else "REACHABLE"
        )

        # Enriquecer la evidencia de Stage 2 con la señal de riesgo
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
                f"[ZeroNoise Depcheck Gate] Señal de riesgo: {risk_signal}. "
                f"Contexto de Stage 3 ensamblado — análisis LLM completo pendiente."
            ),
        )

        final_verdict = verdict_record.get("verdict", heuristic_verdict)
        base["verdict"] = final_verdict
        base["justification"] = (
            f"Paquete '{finding.effective_purl}' es alcanzable en el código fuente. "
            f"Señal de riesgo pre-análisis: {risk_signal}. "
            f"{'BLOQUEO preventivo hasta análisis LLM completo.' if final_verdict == 'LIKELY_EXPLOITABLE' else 'Requiere análisis LLM completo para confirmar explotabilidad.'}"
        )
        base["stage3_context"] = context
        base["stage3_analysis"] = verdict_record

    except Exception as e:
        base["verdict"] = "REACHABLE"
        base["justification"] = (
            f"Stage 3 falló para {finding.cve_id}: {e}. "
            f"El paquete es alcanzable — requiere revisión humana."
        )
        base["requires_human_review"] = True

    return base
