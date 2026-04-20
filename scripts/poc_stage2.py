"""
Proof of Concept — Stage 2: Reachability Analysis

Demonstrates the full Stage 1 → Stage 2 pipeline:
  1. Fetch actionable findings from Dependency-Track (Stage 1)
  2. Scan the local project source to determine package reachability (Stage 2)
  3. Optionally write NOT_AFFECTED verdicts back to DT

Usage:
    # Dry-run (no writes to DT):
    uv run python scripts/poc_stage2.py --project-uuid <uuid> --project-path <path>

    # Write verdicts to Dependency-Track:
    uv run python scripts/poc_stage2.py --project-uuid <uuid> --project-path <path> --apply

    # Quick single-package check:
    uv run python scripts/poc_stage2.py --project-path <path> --package adm-zip
"""

import argparse
import asyncio
import json

from fastmcp import Client

from zeronoise.server import mcp


def _pretty(data: dict | list) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


async def demo_single_package(client: Client, project_path: str, package: str) -> None:
    print("=" * 60)
    print(f"TOOL: analyze_package_reachability  [{package}]")
    print("=" * 60)
    result = await client.call_tool(
        "analyze_package_reachability",
        {"project_path": project_path, "package_name": package},
    )
    data = json.loads(result.content[0].text)
    print(f"Verdict        : {data['verdict']}")
    print(f"Files scanned  : {data['files_scanned']}")
    print(f"Usages found   : {data['usage_count']}")
    if data["usages"]:
        print("\nUsage locations:")
        for u in data["usages"][:5]:
            print(f"  {u['file']}:{u['line']}  →  {u['statement']}")
    print(f"\nAuto-justification:\n  {data['justification']}")


async def demo_import_graph(client: Client, project_path: str) -> None:
    print("\n" + "=" * 60)
    print("TOOL: build_project_import_graph")
    print("=" * 60)
    result = await client.call_tool(
        "build_project_import_graph",
        {"project_path": project_path},
    )
    data = json.loads(result.content[0].text)
    print(f"Files with imports      : {data['files_with_imports']}")
    print(f"Unique packages imported: {data['unique_packages_imported']}")
    print(f"Packages: {', '.join(data['packages'][:20])}")
    if len(data["packages"]) > 20:
        print(f"  ... and {len(data['packages']) - 20} more")


async def demo_full_filter(
    client: Client, project_uuid: str, project_path: str, apply: bool
) -> None:
    print("\n" + "=" * 60)
    print(f"TOOL: run_reachability_filter  [dry_run={not apply}]")
    print("=" * 60)
    result = await client.call_tool(
        "run_reachability_filter",
        {
            "project_uuid": project_uuid,
            "project_path": project_path,
            "dry_run": not apply,
        },
    )
    data = json.loads(result.content[0].text)

    print(f"Project          : {data['project_name']}")
    print(f"Total actionable : {data['total_actionable']}")
    print(f"NOT reachable    : {data['not_reachable_count']}  → would be marked NOT_AFFECTED")
    print(f"Reachable        : {data['reachable_count']}  → pass to Stage 3")
    print(f"Errors           : {data['error_count']}")
    print(f"Noise reduction  : {data['noise_reduction_pct']}%")

    if apply:
        print(f"\n[{'DRY RUN' if data['dry_run'] else 'APPLIED'}] Verdicts written to Dependency-Track: {data['not_reachable_count']}")

    if data["reachable"]:
        print("\nSample reachable findings (→ Stage 3):")
        for f in data["reachable"][:5]:
            print(f"  {f['vuln_id']}  {f['component']}")

    if data["not_reachable"]:
        print("\nSample NOT_AFFECTED findings (eliminated by Stage 2):")
        for f in data["not_reachable"][:5]:
            print(f"  {f['vuln_id']}  {f['component']}")


async def run(
    project_uuid: str | None,
    project_path: str,
    package: str | None,
    apply: bool,
) -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()
        print(f"[MCP] {len(tools)} tools registered: {[t.name for t in tools]}\n")

        if package:
            await demo_single_package(client, project_path, package)
            return

        await demo_import_graph(client, project_path)

        if project_uuid:
            await demo_full_filter(client, project_uuid, project_path, apply)
        else:
            print("\n[!] Provide --project-uuid to run the full reachability filter.")

    print("\n[OK] Stage 2 POC complete.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-uuid", help="DT project UUID")
    parser.add_argument(
        "--project-path",
        required=True,
        help="Absolute path to the project source code on disk",
    )
    parser.add_argument(
        "--package",
        help="Single package to check (skips full filter)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Write NOT_AFFECTED verdicts to Dependency-Track (default: dry-run)",
    )
    args = parser.parse_args()
    asyncio.run(run(args.project_uuid, args.project_path, args.package, args.apply))


if __name__ == "__main__":
    main()
