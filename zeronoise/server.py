import json

from fastmcp import FastMCP

from zeronoise.config import settings
from zeronoise.models.security_policy import DEFAULT_POLICY
from zeronoise.models.vulnerability import AnalysisJustification, VerdictTaxonomy
from zeronoise.tools.code_context import (
    fetch_code_snippet,
    find_symbol_usages,
    get_call_context,
    get_function_context,
)
from zeronoise.tools.decision import generate_finding_verdict, generate_vex_report
from zeronoise.tools.stage3_context import prepare_stage3_context
from zeronoise.tools.reachability import (
    analyze_package_reachability,
    build_project_import_graph,
    run_reachability_filter,
    update_finding_analysis,
)
from zeronoise.tools.sbom_ingestion import (
    get_actionable_findings,
    get_project_findings,
    get_vulnerability_detail,
    list_projects,
)

mcp = FastMCP(settings.mcp_server_name)

# ── Stage 1 — Metadata-First Filter ──────────────────────────────────────────
mcp.tool()(list_projects)
mcp.tool()(get_project_findings)
mcp.tool()(get_actionable_findings)
mcp.tool()(get_vulnerability_detail)

# ── Stage 2 — Reachability Analysis ──────────────────────────────────────────
mcp.tool()(analyze_package_reachability)
mcp.tool()(build_project_import_graph)
mcp.tool()(run_reachability_filter)
mcp.tool()(update_finding_analysis)

# ── Stage 3 — Context Assembly (deterministic, zero tokens) ──────────────────
mcp.tool()(prepare_stage3_context)

# ── Stage 3 — Code Context (bounded snippet access, LLM-driven) ──────────────
mcp.tool()(fetch_code_snippet)
mcp.tool()(get_function_context)
mcp.tool()(get_call_context)
mcp.tool()(find_symbol_usages)

# ── Decision — Verdicts and VEX Report Generation ────────────────────────────
mcp.tool()(generate_finding_verdict)
mcp.tool()(generate_vex_report)


# ── Resources ─────────────────────────────────────────────────────────────────

@mcp.resource("taxonomy://verdicts")
async def resource_verdict_taxonomy() -> str:
    """Canonical verdict and justification taxonomy used by all ZeroNoise tools."""
    return json.dumps({
        "verdicts": [v.value for v in VerdictTaxonomy],
        "justifications": [j.value for j in AnalysisJustification],
        "stage3_eligible_verdicts": ["REACHABLE", "UNKNOWN"],
        "description": {
            "UNKNOWN": "Verdict not yet determined",
            "NOT_REACHABLE": "Package not imported by any application source file",
            "REACHABLE": "Package is imported — requires Stage 3 contextual analysis",
            "LIKELY_EXPLOITABLE": "Reachable and context suggests potential exploitation",
            "EXPLOITABLE": "Confirmed exploitable — block pipeline",
            "FALSE_POSITIVE": "Finding is a false positive — no risk",
            "NOT_APPLICABLE": "Vulnerability does not apply to this project's configuration",
        },
    }, indent=2)


@mcp.resource("policy://analysis-rules")
async def resource_analysis_policy() -> str:
    """Active security policy governing file system access for all scanners."""
    return json.dumps({
        "security_policy": DEFAULT_POLICY.model_dump(),
        "stage3_confidence_threshold": settings.stage3_confidence_threshold,
        "llm_usage_rules": [
            "NEVER load entire files — use fetch_code_snippet with explicit line ranges",
            "ALWAYS truncate large responses to max_snippet_lines",
            "NEVER expose secrets, tokens, or credentials",
            "PRIORITIZE call sites and entry points over surrounding code",
            "Stage 3 MUST NOT run without REACHABLE verdict + evidence + confidence >= threshold",
        ],
    }, indent=2)


@mcp.resource("project://{project_id}/findings")
async def resource_project_findings(project_id: str) -> str:
    """Actionable findings for a project, structured for Stage 2 input."""
    from zeronoise.clients.dependency_track import dt_client
    result = await dt_client.get_project_findings(project_id)
    findings_out = []
    for f in result.actionable:
        d = f.model_dump()
        d["finding_id"] = f.finding_id
        findings_out.append(d)
    return json.dumps({
        "project": result.project.model_dump(),
        "actionable_count": len(findings_out),
        "findings": findings_out,
    }, indent=2)


@mcp.resource("project://{project_id}/reachability-summary")
async def resource_reachability_summary(project_id: str) -> str:
    """
    Reachability summary placeholder.

    Call run_reachability_filter via tool to generate a live summary.
    This resource returns structural metadata only.
    """
    return json.dumps({
        "note": (
            "Run the 'run_reachability_filter' tool with this project_uuid to generate "
            "a full reachability summary. This resource returns schema metadata only."
        ),
        "project_id": project_id,
        "schema": {
            "not_reachable": "list[finding_record]",
            "reachable": "list[finding_record]",
            "stage3_candidates": "list[finding_record — stage3_gate.stage3_allowed == true]",
            "noise_reduction_pct": "float",
            "stage3_confidence_threshold": "float",
        },
    }, indent=2)
