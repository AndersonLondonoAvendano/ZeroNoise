"""
Proof of Concept — Stage 1: Metadata-First Filter

Runs all 4 MCP tools against a real Dependency-Track instance using
fastmcp.Client in-process (no subprocess, no network MCP transport needed).

Usage:
    uv run python scripts/poc_stage1.py
    uv run python scripts/poc_stage1.py --project-uuid <uuid>
"""

import argparse
import asyncio
import json

from fastmcp import Client

from zeronoise.server import mcp


def _pretty(data: dict | list) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


async def run(project_uuid: str | None) -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()
        print(f"[MCP] {len(tools)} tools registered: {[t.name for t in tools]}\n")

        # --- Tool 1: list_projects ---
        print("=" * 60)
        print("TOOL: list_projects")
        print("=" * 60)
        result = await client.call_tool("list_projects", {})
        projects = json.loads(result.content[0].text)
        print(_pretty(projects))

        if not projects:
            print("\n[!] No projects found in Dependency-Track. Stopping POC.")
            return

        target_uuid = project_uuid or projects[0]["uuid"]
        target_name = next(
            (p["name"] for p in projects if p["uuid"] == target_uuid), target_uuid
        )
        print(f'\n[>] Using project: "{target_name}" ({target_uuid})\n')

        # --- Tool 2: get_project_findings ---
        print("=" * 60)
        print("TOOL: get_project_findings")
        print("=" * 60)
        result = await client.call_tool(
            "get_project_findings", {"project_uuid": target_uuid}
        )
        findings_data = json.loads(result.content[0].text)
        print(f"Total findings : {findings_data['total_findings']}")
        print(f"Actionable     : {findings_data['actionable_count']}")
        if findings_data["findings"]:
            print("\nFirst finding sample:")
            print(_pretty(findings_data["findings"][0]))

        # --- Tool 3: get_actionable_findings ---
        print("\n" + "=" * 60)
        print("TOOL: get_actionable_findings")
        print("=" * 60)
        result = await client.call_tool(
            "get_actionable_findings", {"project_uuid": target_uuid}
        )
        actionable = json.loads(result.content[0].text)
        print(f"Actionable findings ready for Stage 2: {actionable['actionable_count']}")

        if actionable["findings"]:
            first = actionable["findings"][0]
            vuln = first["vulnerability"]
            comp = first["component"]
            print(f"\n  CVE    : {vuln['vuln_id']} ({vuln['severity']})")
            print(f"  Comp   : {comp['name']} {comp.get('version', '')}")
            print(f"  Score  : {vuln.get('cvss_v3_score', 'N/A')}")
            print(f"  Funcs  : {vuln['vulnerable_functions'] or 'not in advisory metadata'}")

            # --- Tool 4: get_vulnerability_detail ---
            print("\n" + "=" * 60)
            print("TOOL: get_vulnerability_detail")
            print("=" * 60)
            result = await client.call_tool(
                "get_vulnerability_detail",
                {"source": vuln["source"], "vuln_id": vuln["vuln_id"]},
            )
            detail = json.loads(result.content[0].text)
            print(_pretty(detail))

    print("\n[OK] Stage 1 POC complete.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project-uuid",
        help="DT project UUID to audit (defaults to first project found)",
    )
    args = parser.parse_args()
    asyncio.run(run(args.project_uuid))


if __name__ == "__main__":
    main()