import httpx

from zeronoise.config import settings
from zeronoise.models.vulnerability import (
    AnalysisState,
    Component,
    Finding,
    Project,
    ProjectFindings,
    Severity,
    Vulnerability,
    VulnerableFunction,
)

_DT_API = f"{settings.dt_base_url.rstrip('/')}/api/v1"
_HEADERS = {"X-Api-Key": settings.dt_api_key, "Accept": "application/json"}


def _parse_vulnerable_functions(raw: dict) -> list[VulnerableFunction]:
    """
    DT/OSV advisories may include affected ranges with function-level detail.
    We extract from `affectedVersionRange` or `detail` as a best-effort.
    """
    funcs: list[VulnerableFunction] = []

    # GitHub / OSV advisories sometimes embed function names in `detail`
    for affected in raw.get("affectedPackages", []):
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                if func := event.get("introduced_function"):
                    parts = func.rsplit(".", 1)
                    funcs.append(
                        VulnerableFunction(
                            module=parts[0] if len(parts) == 2 else func,
                            function_name=parts[-1],
                        )
                    )
    return funcs


def _parse_finding(raw: dict) -> Finding:
    comp_raw = raw["component"]
    vuln_raw = raw["vulnerability"]
    analysis_raw = raw.get("analysis", {})

    component = Component(
        uuid=comp_raw["uuid"],
        name=comp_raw["name"],
        version=comp_raw.get("version"),
        purl=comp_raw.get("purl"),
        group=comp_raw.get("group"),
    )

    vulnerability = Vulnerability(
        uuid=vuln_raw["uuid"],
        vuln_id=vuln_raw["vulnId"],
        source=vuln_raw.get("source", "UNKNOWN"),
        severity=Severity(vuln_raw.get("severity", "UNASSIGNED")),
        cvss_v3_score=vuln_raw.get("cvssV3BaseScore"),
        description=vuln_raw.get("description"),
        vulnerable_functions=_parse_vulnerable_functions(vuln_raw),
    )

    return Finding(
        component=component,
        vulnerability=vulnerability,
        analysis_state=AnalysisState(
            analysis_raw.get("state", AnalysisState.NOT_SET)
        ),
        is_suppressed=analysis_raw.get("isSuppressed", False),
    )


class DependencyTrackClient:
    async def list_projects(self, page_size: int = 100) -> list[Project]:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=30) as client:
            params = {"pageSize": page_size, "pageNumber": 1}
            projects: list[Project] = []

            while True:
                response = await client.get(f"{_DT_API}/project", params=params)
                response.raise_for_status()
                batch = response.json()
                if not batch:
                    break
                projects.extend(
                    Project(
                        uuid=p["uuid"],
                        name=p["name"],
                        version=p.get("version"),
                        description=p.get("description"),
                        active=p.get("active", True),
                    )
                    for p in batch
                )
                if len(batch) < page_size:
                    break
                params["pageNumber"] += 1

            return projects

    async def get_project_findings(self, project_uuid: str) -> ProjectFindings:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=30) as client:
            proj_resp = await client.get(f"{_DT_API}/project/{project_uuid}")
            proj_resp.raise_for_status()
            proj_raw = proj_resp.json()

            findings_resp = await client.get(
                f"{_DT_API}/finding/project/{project_uuid}"
            )
            findings_resp.raise_for_status()

        project = Project(
            uuid=proj_raw["uuid"],
            name=proj_raw["name"],
            version=proj_raw.get("version"),
            description=proj_raw.get("description"),
            active=proj_raw.get("active", True),
        )

        findings = [_parse_finding(f) for f in findings_resp.json()]
        return ProjectFindings(project=project, findings=findings)

    async def get_vulnerability(self, source: str, vuln_id: str) -> dict:
        """Raw vulnerability detail from DT — used for enrichment in Stage 3."""
        async with httpx.AsyncClient(headers=_HEADERS, timeout=30) as client:
            response = await client.get(
                f"{_DT_API}/vulnerability/source/{source}/vuln/{vuln_id}"
            )
            response.raise_for_status()
            return response.json()

    async def update_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
        state: str,
        justification: str = "CODE_NOT_REACHABLE",
        details: str = "",
        suppressed: bool = False,
    ) -> dict:
        """
        Write a reachability verdict back to Dependency-Track.

        Args:
            state: AnalysisState value — NOT_AFFECTED, IN_TRIAGE, EXPLOITABLE, etc.
            justification: DT justification code — CODE_NOT_REACHABLE is the
                           correct value when Stage 2 finds no import path.
        """
        payload = {
            "project": project_uuid,
            "component": component_uuid,
            "vulnerability": vulnerability_uuid,
            "analysisState": state,
            "analysisJustification": justification,
            "analysisDetails": details,
            "isSuppressed": suppressed,
        }
        async with httpx.AsyncClient(headers=_HEADERS, timeout=30) as client:
            response = await client.put(f"{_DT_API}/analysis", json=payload)
            response.raise_for_status()
            return response.json()


dt_client = DependencyTrackClient()
