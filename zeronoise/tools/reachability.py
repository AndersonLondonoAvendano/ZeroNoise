"""
Stage 2 — Reachability Analysis

MCP tools that determine whether a vulnerable npm package is actually
imported by the application source code. Operates entirely on the local
filesystem — zero LLM tokens consumed.

Findings that are NOT reachable are marked NOT_AFFECTED in Dependency-Track
automatically, with a machine-generated justification comment.
"""

from zeronoise.analyzers.js_import_scanner import build_import_graph, scan_project
from zeronoise.clients.dependency_track import dt_client


async def analyze_package_reachability(project_path: str, package_name: str) -> dict:
    """
    Determine whether an npm package is imported anywhere in the project source.

    Scans all .js/.ts/.mjs/.cjs/.jsx/.tsx files under `project_path`,
    skipping node_modules, dist, build and other non-source directories.

    Args:
        project_path: Absolute path to the project's source root on disk.
        package_name: npm package name or PURL (e.g. 'adm-zip' or
                      'pkg:npm/adm-zip@0.4.7').

    Returns a reachability report with verdict, file count, and usage locations.
    """
    result = scan_project(project_path, package_name)
    return {
        "package": result.package,
        "verdict": result.verdict,
        "is_reachable": result.is_reachable,
        "files_scanned": result.files_scanned,
        "usage_count": len(result.usages),
        "usages": [u.model_dump() for u in result.usages],
        "justification": result.auto_justification,
    }


async def build_project_import_graph(project_path: str) -> dict:
    """
    Build a full import map of the project: {file → [packages it imports]}.

    Useful for the AI to understand the overall dependency surface before
    deciding which findings to investigate further.

    Args:
        project_path: Absolute path to the project's source root on disk.
    """
    graph = build_import_graph(project_path)
    all_packages: set[str] = set()
    for pkgs in graph.values():
        all_packages.update(pkgs)

    return {
        "project_path": project_path,
        "files_with_imports": len(graph),
        "unique_packages_imported": len(all_packages),
        "packages": sorted(all_packages),
        "graph": graph,
    }


async def run_reachability_filter(
    project_uuid: str,
    project_path: str,
    dry_run: bool = True,
) -> dict:
    """
    Run Stage 2 over ALL actionable findings of a project.

    For each finding:
      - Scans source code for imports of the vulnerable package.
      - If NOT reachable → optionally writes NOT_AFFECTED to Dependency-Track.
      - If reachable → leaves the finding for Stage 3 contextual analysis.

    Args:
        project_uuid: Dependency-Track project UUID.
        project_path: Absolute path to the project source on disk.
        dry_run: When True, performs analysis but does NOT write back to DT.
                 Set to False to update findings in Dependency-Track.

    Returns a summary with per-finding verdicts.
    """
    from zeronoise.clients.dependency_track import dt_client
    from zeronoise.analyzers.js_import_scanner import scan_project

    project_findings = await dt_client.get_project_findings(project_uuid)
    actionable = project_findings.actionable

    not_reachable: list[dict] = []
    reachable: list[dict] = []
    errors: list[dict] = []

    # Deduplicate: same package may have multiple CVEs — scan once per package
    scanned_cache: dict[str, object] = {}

    for finding in actionable:
        pkg_name = finding.component.name
        try:
            if pkg_name not in scanned_cache:
                scanned_cache[pkg_name] = scan_project(project_path, pkg_name)
            result = scanned_cache[pkg_name]

            record = {
                "vuln_id": finding.vulnerability.vuln_id,
                "component": f"{finding.component.name}@{finding.component.version}",
                "component_uuid": finding.component.uuid,
                "vulnerability_uuid": finding.vulnerability.uuid,
                "verdict": result.verdict,
                "files_scanned": result.files_scanned,
                "usage_count": len(result.usages),
            }

            if not result.is_reachable:
                not_reachable.append(record)
                if not dry_run:
                    await dt_client.update_analysis(
                        project_uuid=project_uuid,
                        component_uuid=finding.component.uuid,
                        vulnerability_uuid=finding.vulnerability.uuid,
                        state="NOT_AFFECTED",
                        justification="CODE_NOT_REACHABLE",
                        details=result.auto_justification,
                    )
            else:
                reachable.append(record)

        except Exception as exc:
            errors.append({"vuln_id": finding.vulnerability.vuln_id, "error": str(exc)})

    return {
        "project_uuid": project_uuid,
        "project_name": project_findings.project.name,
        "dry_run": dry_run,
        "total_actionable": len(actionable),
        "not_reachable_count": len(not_reachable),
        "reachable_count": len(reachable),
        "error_count": len(errors),
        "noise_reduction_pct": round(len(not_reachable) / len(actionable) * 100, 1) if actionable else 0,
        "not_reachable": not_reachable,
        "reachable": reachable,
        "errors": errors,
    }


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

    Args:
        state: NOT_AFFECTED | IN_TRIAGE | EXPLOITABLE | FALSE_POSITIVE
        details: Human-readable justification written to the DT analysis comment.
        suppressed: Whether to suppress the finding from the dashboard.
    """
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
