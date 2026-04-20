"""
Stage 1 - Metadata-First Filter

MCP tools that ingest SBOM vulnerability metadata from Dependency-Track.
The AI calls these tools to build a structured picture of CVEs and their
entry points BEFORE consuming tokens on source code analysis.
"""

from zeronoise.clients.dependency_track import dt_client
from zeronoise.models.vulnerability import ProjectFindings


async def list_projects() -> list[dict]:
    """
    List all projects tracked in Dependency-Track.

    Returns a lightweight list so the AI can choose which project to audit
    without pulling full vulnerability data upfront.
    """
    projects = await dt_client.list_projects()
    return [p.model_dump() for p in projects]


async def get_project_findings(project_uuid: str) -> dict:
    """
    Fetch all CVE findings for a project from Dependency-Track.

    Returns structured metadata including:
    - Component name, version, and PURL
    - CVE ID, severity, and CVSS score
    - Known vulnerable functions/classes (entry points)
    - Current analysis state (suppressed, false positive, etc.)

    Only actionable findings (not suppressed, not already marked NOT_AFFECTED)
    are candidates for Stage 2 reachability analysis.
    """
    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    return {
        "project": result.project.model_dump(),
        "total_findings": len(result.findings),
        "actionable_count": len(result.actionable),
        "findings": [f.model_dump() for f in result.findings],
    }


async def get_actionable_findings(project_uuid: str) -> dict:
    """
    Return only the findings that require further investigation.

    Filters out suppressed findings and those already marked as NOT_AFFECTED
    or FALSE_POSITIVE, reducing noise before Stage 2 begins.
    """
    result: ProjectFindings = await dt_client.get_project_findings(project_uuid)
    return {
        "project": result.project.model_dump(),
        "actionable_count": len(result.actionable),
        "findings": [f.model_dump() for f in result.actionable],
    }


async def get_vulnerability_detail(source: str, vuln_id: str) -> dict:
    """
    Fetch raw vulnerability detail from Dependency-Track for a specific CVE.

    Use this to enrich a finding with additional context (references, CWEs,
    affected version ranges) when entry points are not embedded in the finding.

    Args:
        source: Advisory source (NVD, GITHUB, OSV, SNYK, etc.)
        vuln_id: CVE or advisory ID (e.g. CVE-2023-1234 or GHSA-xxxx-yyyy-zzzz)
    """
    return await dt_client.get_vulnerability(source, vuln_id)
