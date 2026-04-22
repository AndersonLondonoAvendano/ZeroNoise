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

from zeronoise.audit import audit_tool
from zeronoise.clients.dependency_track import dt_client
from zeronoise.models.vulnerability import ProjectFindings


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


@audit_tool(side_effects="none")
async def get_project_findings(project_uuid: str) -> dict:
    """
    Fetch all CVE findings for a project from Dependency-Track.

    Returns structured metadata including:
    - Component name, version, and PURL
    - CVE ID, severity, and CVSS score
    - Known vulnerable functions/classes (entry points)
    - Current analysis state (suppressed, false positive, etc.)
    - finding_id (component_uuid:vulnerability_uuid) for canonical referencing

    Only actionable findings (not suppressed, not already marked NOT_AFFECTED)
    are candidates for Stage 2 reachability analysis.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic
    """
    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    findings_out = []
    for f in result.findings:
        d = f.model_dump()
        d["finding_id"] = f.finding_id
        findings_out.append(d)

    return {
        "project": result.project.model_dump(),
        "total_findings": len(result.findings),
        "actionable_count": len(result.actionable),
        "findings": findings_out,
    }


@audit_tool(side_effects="none")
async def get_actionable_findings(project_uuid: str) -> dict:
    """
    Return only the findings that require further investigation.

    Filters out suppressed findings and those already marked as NOT_AFFECTED
    or FALSE_POSITIVE, reducing noise before Stage 2 begins.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic
    """
    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    findings_out = []
    for f in result.actionable:
        d = f.model_dump()
        d["finding_id"] = f.finding_id
        findings_out.append(d)

    return {
        "project": result.project.model_dump(),
        "actionable_count": len(result.actionable),
        "findings": findings_out,
    }


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
    return await dt_client.get_vulnerability(source, vuln_id)
