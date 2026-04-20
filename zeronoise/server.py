from fastmcp import FastMCP

from zeronoise.config import settings
from zeronoise.tools.sbom_ingestion import (
    get_actionable_findings,
    get_project_findings,
    get_vulnerability_detail,
    list_projects,
)
from zeronoise.tools.reachability import (
    analyze_package_reachability,
    build_project_import_graph,
    run_reachability_filter,
    update_finding_analysis,
)

mcp = FastMCP(settings.mcp_server_name)

# Stage 1 — Metadata-First Filter
mcp.tool()(list_projects)
mcp.tool()(get_project_findings)
mcp.tool()(get_actionable_findings)
mcp.tool()(get_vulnerability_detail)

# Stage 2 — Reachability Analysis
mcp.tool()(analyze_package_reachability)
mcp.tool()(build_project_import_graph)
mcp.tool()(run_reachability_filter)
mcp.tool()(update_finding_analysis)
