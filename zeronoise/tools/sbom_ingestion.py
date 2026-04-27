"""
Stage 1 - Metadata-First Filter

MCP tools that ingest SBOM vulnerability metadata from Dependency-Track.
The AI calls these tools to build a structured picture of CVEs and their
entry points BEFORE consuming tokens on source code analysis.

Tool contracts:
  list_projects              read_only: true | side_effects: none | cost: low  | deterministic
  get_project_findings       read_only: true | side_effects: none | cost: low  | deterministic
  get_actionable_findings    read_only: true | side_effects: none | cost: low  | deterministic
  get_vulnerability_detail   read_only: true | side_effects: none | cost: low  | deterministic
"""

from zeronoise.audit import audit_tool, safe_tool
from zeronoise.clients.dependency_track import dt_client
from zeronoise.config import settings
from zeronoise.models.vulnerability import ProjectFindings
from zeronoise.tools._validators import _validate_uuid

_MAX_FINDINGS_PER_RESPONSE: int = settings.max_findings_per_response


@safe_tool
@audit_tool(side_effects="none")
async def list_projects() -> list[dict]:
    """
    List all projects tracked in Dependency-Track.

    Returns a lightweight list so the AI can choose which project to audit
    without pulling full vulnerability data upfront.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic
    """
    projects = await dt_client.list_projects()
    return [p.model_dump() for p in projects]


@safe_tool
@audit_tool(side_effects="none")
async def get_project_findings(project_uuid: str, offset: int = 0) -> dict:
    """
    Fetch all CVE findings for a project from Dependency-Track.

    Returns structured metadata including:
    - Component name, version, and PURL
    - CVE ID, severity, and CVSS score
    - Known vulnerable functions/classes (entry points)
    - Current analysis state (suppressed, false positive, etc.)
    - finding_id (component_uuid:vulnerability_uuid) for canonical referencing

    Results are paginated: up to MAX_FINDINGS_PER_RESPONSE items per call.
    Use the returned `next_offset` value to fetch subsequent pages.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_uuid: Dependency-Track project UUID.
        offset: Starting index for pagination (default 0).
    """
    _validate_uuid(project_uuid, "project_uuid")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError(f"offset debe ser un entero >= 0, recibido: {offset!r}")

    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    findings_out = []
    for f in result.findings:
        d = f.model_dump()
        d["finding_id"] = f.finding_id
        findings_out.append(d)

    page = findings_out[offset: offset + _MAX_FINDINGS_PER_RESPONSE]
    has_more = len(findings_out) > offset + _MAX_FINDINGS_PER_RESPONSE
    next_offset = offset + _MAX_FINDINGS_PER_RESPONSE if has_more else None

    return {
        "project": result.project.model_dump(),
        "total_findings": len(result.findings),
        "actionable_count": len(result.actionable),
        "returned_count": len(page),
        "offset": offset,
        "has_more": has_more,
        "next_offset": next_offset,
        "pagination_note": (
            f"Usar offset={next_offset} para obtener los siguientes findings."
            if has_more else "Todos los findings han sido retornados."
        ),
        "findings": page,
    }


@safe_tool
@audit_tool(side_effects="none")
async def get_actionable_findings(project_uuid: str, offset: int = 0) -> dict:
    """
    Return only the findings that require further investigation.

    Filters out suppressed findings and those already marked as NOT_AFFECTED
    or FALSE_POSITIVE, reducing noise before Stage 2 begins.

    Results are paginated: up to MAX_FINDINGS_PER_RESPONSE items per call.
    Use the returned `next_offset` value to fetch subsequent pages.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_uuid: Dependency-Track project UUID.
        offset: Starting index for pagination (default 0).
    """
    _validate_uuid(project_uuid, "project_uuid")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError(f"offset debe ser un entero >= 0, recibido: {offset!r}")

    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    findings_out = []
    for f in result.actionable:
        d = f.model_dump()
        d["finding_id"] = f.finding_id
        findings_out.append(d)

    page = findings_out[offset: offset + _MAX_FINDINGS_PER_RESPONSE]
    has_more = len(findings_out) > offset + _MAX_FINDINGS_PER_RESPONSE
    next_offset = offset + _MAX_FINDINGS_PER_RESPONSE if has_more else None

    return {
        "project": result.project.model_dump(),
        "actionable_count": len(result.actionable),
        "returned_count": len(page),
        "offset": offset,
        "has_more": has_more,
        "next_offset": next_offset,
        "pagination_note": (
            f"Usar offset={next_offset} para obtener los siguientes findings."
            if has_more else "Todos los findings han sido retornados."
        ),
        "findings": page,
    }


@safe_tool
@audit_tool(side_effects="none")
async def get_vulnerability_detail(source: str, vuln_id: str) -> dict:
    """
    Fetch raw vulnerability detail from Dependency-Track for a specific CVE.

    Use this to enrich a finding with additional context (references, CWEs,
    affected version ranges) when entry points are not embedded in the finding.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        source: Advisory source (NVD, GITHUB, OSV, SNYK, etc.)
        vuln_id: CVE or advisory ID (e.g. CVE-2023-1234 or GHSA-xxxx-yyyy-zzzz)
    """
    if not source or not source.strip():
        raise ValueError("source no puede estar vacío")
    if not vuln_id or not vuln_id.strip():
        raise ValueError("vuln_id no puede estar vacío")
    if len(vuln_id) > 100:
        raise ValueError(f"vuln_id excede la longitud máxima permitida: {len(vuln_id)}")

    return await dt_client.get_vulnerability(source, vuln_id)
