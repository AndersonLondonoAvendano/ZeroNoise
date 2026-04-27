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

# Structured timeouts: fast connect, generous read for large finding lists
_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


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


def _safe_url(url: str) -> str:
    """Return URL with any query params stripped — safe to log without leaking tokens."""
    return url.split("?")[0]


class DependencyTrackClient:
    async def list_projects(self, page_size: int = 100) -> list[Project]:
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
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
        except httpx.TimeoutException as exc:
            url = _safe_url(str(exc.request.url)) if exc.request else _DT_API
            raise TimeoutError(
                f"Timeout conectando a Dependency-Track en {url}. "
                "Verificar que el servidor esté disponible."
            ) from exc

    async def get_project_findings(self, project_uuid: str) -> ProjectFindings:
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
                proj_resp = await client.get(f"{_DT_API}/project/{project_uuid}")
                proj_resp.raise_for_status()
                proj_raw = proj_resp.json()

                findings_resp = await client.get(
                    f"{_DT_API}/finding/project/{project_uuid}"
                )
                findings_resp.raise_for_status()
        except httpx.TimeoutException as exc:
            url = _safe_url(str(exc.request.url)) if exc.request else _DT_API
            raise TimeoutError(
                f"Timeout obteniendo findings desde Dependency-Track en {url}."
            ) from exc

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
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
                response = await client.get(
                    f"{_DT_API}/vulnerability/source/{source}/vuln/{vuln_id}"
                )
                response.raise_for_status()
                return response.json()
        except httpx.TimeoutException as exc:
            url = _safe_url(str(exc.request.url)) if exc.request else _DT_API
            raise TimeoutError(
                f"Timeout obteniendo detalle de vulnerabilidad desde Dependency-Track en {url}."
            ) from exc

    async def get_analysis(
        self,
        project_uuid: str,
        component_uuid: str,
        vulnerability_uuid: str,
    ) -> dict:
        """
        Fetch the current analysis state for a specific finding.

        Returns {"analysisState": "NOT_SET"} when no analysis exists yet (HTTP 404).
        Used by verdict immutability checks before overwriting an existing state.
        """
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
                response = await client.get(
                    f"{_DT_API}/analysis",
                    params={
                        "component": component_uuid,
                        "project": project_uuid,
                        "vulnerability": vulnerability_uuid,
                    },
                )
                if response.status_code == 404:
                    return {"analysisState": "NOT_SET"}
                response.raise_for_status()
                return response.json()
        except httpx.TimeoutException as exc:
            url = _safe_url(str(exc.request.url)) if exc.request else _DT_API
            raise TimeoutError(
                f"Timeout consultando estado de análisis en Dependency-Track en {url}."
            ) from exc

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
        try:
            async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
                response = await client.put(f"{_DT_API}/analysis", json=payload)
                response.raise_for_status()
                return response.json()
        except httpx.TimeoutException as exc:
            url = _safe_url(str(exc.request.url)) if exc.request else _DT_API
            raise TimeoutError(
                f"Timeout escribiendo análisis en Dependency-Track en {url}."
            ) from exc


dt_client = DependencyTrackClient()
