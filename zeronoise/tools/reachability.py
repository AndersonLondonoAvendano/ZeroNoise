"""
Stage 2 — Reachability Analysis

MCP tools that determine whether a vulnerable package is actually imported
by the application source code. Operates entirely on the local filesystem —
zero LLM tokens consumed.

Supports: JavaScript / TypeScript (npm) and Java (Maven / Gradle).
Language is auto-detected from the package PURL or project markers.

Findings that are NOT reachable are marked NOT_AFFECTED in Dependency-Track
automatically, with a machine-generated justification comment.

Tool contracts:
  analyze_package_reachability  read_only: true  | side_effects: none          | cost: low  | deterministic
  build_project_import_graph    read_only: true  | side_effects: none          | cost: low  | deterministic
  run_reachability_filter       read_only: false | side_effects: external_write | cost: low  | deterministic
  update_finding_analysis       read_only: false | side_effects: external_write | cost: low  | deterministic
"""

from zeronoise.analyzers.scanner_factory import detect_language, get_scanner
from zeronoise.audit import audit_tool, safe_tool
from zeronoise.clients.dependency_track import dt_client
from zeronoise.config import settings
from zeronoise.tools._validators import (
    _validate_package_name,
    _validate_project_path,
    _validate_uuid,
)

# ── Verdict immutability ───────────────────────────────────────────────────────
# Verdicts can only advance in severity — never be downgraded.
_STATE_HIERARCHY: dict[str, int] = {
    "NOT_SET": 0,
    "IN_TRIAGE": 1,
    "NOT_AFFECTED": 2,
    "FALSE_POSITIVE": 2,
    "EXPLOITABLE": 3,
}


def _can_overwrite(current_state: str, new_state: str) -> bool:
    """Return True only if new_state has equal or greater severity than current_state."""
    return _STATE_HIERARCHY.get(new_state, 0) >= _STATE_HIERARCHY.get(current_state, 0)


# ── Stage 3 gate ───────────────────────────────────────────────────────────────

def _stage3_gate(
    verdict: str,
    evidence: list[dict],
    confidence: float,
) -> dict:
    """
    Evaluate whether Stage 3 LLM analysis is allowed.

    Stage 3 MUST NOT run unless:
      - verdict is REACHABLE
      - evidence is non-empty
      - confidence >= settings.stage3_confidence_threshold
    """
    threshold = settings.stage3_confidence_threshold
    if verdict != "REACHABLE":
        return {
            "stage3_allowed": False,
            "reason": f"Verdict '{verdict}' does not require contextual analysis",
        }
    if not evidence:
        return {
            "stage3_allowed": False,
            "reason": "No evidence available — cannot justify Stage 3 execution",
        }
    if confidence < threshold:
        return {
            "stage3_allowed": False,
            "reason": (
                f"Confidence {confidence:.2f} is below threshold {threshold:.2f} — "
                "human review recommended"
            ),
        }
    return {
        "stage3_allowed": True,
        "reason": (
            f"Reachable with {len(evidence)} evidence item(s) at "
            f"confidence {confidence:.2f} (threshold {threshold:.2f})"
        ),
    }


def _resolve_package_identifier(component) -> str:
    """
    Build the best package identifier for a DT component.

    Priority:
      1. PURL (most complete — includes ecosystem, groupId, version)
      2. Maven GAV from group + name
      3. Plain component.name (npm fallback)
    """
    if component.purl:
        return component.purl
    if component.group:
        # Maven-style: groupId/artifactId maps to pkg:maven/groupId/artifactId
        return f"pkg:maven/{component.group}/{component.name}"
    return component.name


# ── Tools ──────────────────────────────────────────────────────────────────────

@safe_tool
@audit_tool(side_effects="none")
async def analyze_package_reachability(
    project_path: str,
    package_name: str,
    language: str = "auto",
) -> dict:
    """
    Determine whether a package is imported anywhere in the project source.

    Supports JavaScript/TypeScript (npm) and Java (Maven/Gradle). Language is
    auto-detected from the PURL scheme or project markers when language="auto".

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_path: Absolute path to the project's source root on disk.
        package_name: Package name or PURL.
                      JS: 'adm-zip'  or 'pkg:npm/adm-zip@0.4.7'
                      Java: 'pkg:maven/org.springframework/spring-core@5.3.0'
                            or 'org.springframework:spring-core'
        language: "auto" | "javascript" | "java"
    """
    _validate_project_path(project_path)
    _validate_package_name(package_name)

    if language == "auto":
        language = detect_language(project_path, package_name)

    scanner = get_scanner(language)
    result = scanner.scan_project(project_path, package_name)
    evidence = [u.model_dump() for u in result.usages]
    gate = _stage3_gate(result.verdict, evidence, result.confidence)

    return {
        "package": result.package,
        "language": result.language,
        "verdict": result.verdict,
        "is_reachable": result.is_reachable,
        "files_scanned": result.files_scanned,
        "confidence": result.confidence,
        "confidence_reason": result.confidence_reason,
        "limitations": result.limitations,
        "requires_human_review": result.requires_human_review,
        "usage_count": len(result.usages),
        "evidence": evidence,
        "justification": result.auto_justification,
        "stage3_gate": gate,
        "reproducibility": result.reproducibility.model_dump() if result.reproducibility else None,
    }


@safe_tool
@audit_tool(side_effects="none")
async def build_project_import_graph(
    project_path: str,
    language: str = "auto",
) -> dict:
    """
    Build a full import map of the project: {file → [packages it imports]}.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_path: Absolute path to the project's source root on disk.
        language: "auto" | "javascript" | "java"
    """
    _validate_project_path(project_path)

    if language == "auto":
        language = detect_language(project_path, "")

    scanner = get_scanner(language)
    graph = scanner.build_import_graph(project_path)
    all_packages: set[str] = set()
    for pkgs in graph.values():
        all_packages.update(pkgs)

    return {
        "project_path": project_path,
        "language": language,
        "files_with_imports": len(graph),
        "unique_packages_imported": len(all_packages),
        "packages": sorted(all_packages),
        "graph": graph,
    }


@safe_tool
@audit_tool(side_effects="external_write")
async def run_reachability_filter(
    project_uuid: str,
    project_path: str,
    dry_run: bool = True,
    language: str = "auto",
) -> dict:
    """
    Run Stage 2 over ALL actionable findings of a project.

    For each finding:
      - Resolves the canonical package identifier (PURL > Maven GAV > name).
      - Scans source code using the language-appropriate scanner.
      - If NOT reachable → optionally writes NOT_AFFECTED to Dependency-Track.
      - If reachable → evaluates Stage 3 gate.

    Contract:
        read_only: false (when dry_run=False)
        side_effects: external_write (when dry_run=False)
        requires_confirmation: true (when dry_run=False)
        expected_cost: low
        determinism: deterministic

    Args:
        project_uuid: Dependency-Track project UUID.
        project_path: Absolute path to the project source on disk.
        dry_run: When True, performs analysis but does NOT write back to DT.
        language: "auto" | "javascript" | "java"
    """
    _validate_uuid(project_uuid, "project_uuid")
    _validate_project_path(project_path)

    project_findings = await dt_client.get_project_findings(project_uuid)
    actionable = project_findings.actionable

    # Detect language once for the whole project if auto
    resolved_language = language
    if resolved_language == "auto":
        resolved_language = detect_language(project_path, "")
        # Re-check using the first finding's PURL for stronger signal
        if actionable and actionable[0].component.purl:
            resolved_language = detect_language(project_path, actionable[0].component.purl)

    scanner = get_scanner(resolved_language)

    not_reachable: list[dict] = []
    reachable: list[dict] = []
    stage3_candidates: list[dict] = []
    errors: list[dict] = []

    # Cache keyed on the normalized import prefix (after scanner resolution)
    # This correctly deduplicates Java findings with the same groupId prefix
    scanned_cache: dict[str, object] = {}

    for finding in actionable:
        pkg_id = _resolve_package_identifier(finding.component)
        try:
            # Use the PURL/GAV as cache key to avoid re-scanning the same package
            cache_key = pkg_id
            if cache_key not in scanned_cache:
                scanned_cache[cache_key] = scanner.scan_project(project_path, pkg_id)
            result = scanned_cache[cache_key]

            evidence = [u.model_dump() for u in result.usages]
            gate = _stage3_gate(result.verdict, evidence, result.confidence)

            record = {
                "finding_id": finding.finding_id,
                "vuln_id": finding.vulnerability.vuln_id,
                "component": f"{finding.component.name}@{finding.component.version}",
                "component_uuid": finding.component.uuid,
                "vulnerability_uuid": finding.vulnerability.uuid,
                "package_resolved": result.package,
                "language": result.language,
                "verdict": result.verdict,
                "files_scanned": result.files_scanned,
                "usage_count": len(result.usages),
                "confidence": result.confidence,
                "confidence_reason": result.confidence_reason,
                "requires_human_review": result.requires_human_review,
                "stage3_gate": gate,
            }

            if not result.is_reachable:
                not_reachable.append(record)
                if not dry_run:
                    current_state = str(finding.analysis_state)
                    if _can_overwrite(current_state, "NOT_AFFECTED"):
                        await dt_client.update_analysis(
                            project_uuid=project_uuid,
                            component_uuid=finding.component.uuid,
                            vulnerability_uuid=finding.vulnerability.uuid,
                            state="NOT_AFFECTED",
                            justification="CODE_NOT_REACHABLE",
                            details=result.auto_justification,
                        )
                    else:
                        errors.append({
                            "vuln_id": finding.vulnerability.vuln_id,
                            "error": (
                                f"Overwrite bloqueado: estado actual '{current_state}' "
                                f"tiene mayor severidad que 'NOT_AFFECTED'."
                            ),
                        })
            else:
                reachable.append(record)
                if gate["stage3_allowed"]:
                    stage3_candidates.append(record)

        except Exception as exc:
            errors.append({"vuln_id": finding.vulnerability.vuln_id, "error": str(exc)})

    return {
        "project_uuid": project_uuid,
        "project_name": project_findings.project.name,
        "language": resolved_language,
        "dry_run": dry_run,
        "total_actionable": len(actionable),
        "not_reachable_count": len(not_reachable),
        "reachable_count": len(reachable),
        "stage3_candidates_count": len(stage3_candidates),
        "error_count": len(errors),
        "noise_reduction_pct": (
            round(len(not_reachable) / len(actionable) * 100, 1) if actionable else 0
        ),
        "stage3_confidence_threshold": settings.stage3_confidence_threshold,
        "not_reachable": not_reachable,
        "reachable": reachable,
        "stage3_candidates": stage3_candidates,
        "errors": errors,
    }


@safe_tool
@audit_tool(side_effects="external_write")
async def update_finding_analysis(
    project_uuid: str,
    component_uuid: str,
    vulnerability_uuid: str,
    state: str,
    details: str,
    suppressed: bool = False,
) -> dict:
    """
    Manually write a reachability verdict for a single finding in Dependency-Track.

    Enforces verdict immutability: the current state in DT is fetched before writing.
    A verdict can only advance in severity — it cannot be downgraded.

    Contract:
        read_only: false
        side_effects: external_write
        requires_confirmation: true
        expected_cost: low
        determinism: deterministic

    Args:
        state: NOT_AFFECTED | IN_TRIAGE | EXPLOITABLE | FALSE_POSITIVE
        details: Human-readable justification written to the DT analysis comment.
        suppressed: Whether to suppress the finding from the dashboard.
    """
    _validate_uuid(project_uuid, "project_uuid")
    _validate_uuid(component_uuid, "component_uuid")
    _validate_uuid(vulnerability_uuid, "vulnerability_uuid")

    allowed_states = {"NOT_AFFECTED", "IN_TRIAGE", "EXPLOITABLE", "FALSE_POSITIVE", "NOT_SET"}
    if state not in allowed_states:
        raise ValueError(
            f"state inválido: {state!r}. Valores permitidos: {sorted(allowed_states)}"
        )

    # Fetch current state to enforce immutability
    current_analysis = await dt_client.get_analysis(
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
    )
    current_state = current_analysis.get("analysisState", "NOT_SET")

    if not _can_overwrite(current_state, state):
        return {
            "blocked": True,
            "reason": (
                f"Overwrite bloqueado: el estado actual '{current_state}' tiene mayor "
                f"severidad que el nuevo estado '{state}'. "
                "Los verdicts no pueden retroceder a menor severidad."
            ),
            "current_state": current_state,
            "requested_state": state,
        }

    justification = "CODE_NOT_REACHABLE" if state == "NOT_AFFECTED" else "NOT_SET"
    return await dt_client.update_analysis(
        project_uuid=project_uuid,
        component_uuid=component_uuid,
        vulnerability_uuid=vulnerability_uuid,
        state=state,
        justification=justification,
        details=details,
        suppressed=suppressed,
    )
