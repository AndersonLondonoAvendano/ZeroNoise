"""
Proof of Concept — Stage 3: Contextual LLM Analysis

Demonstrates the full Stage 1 → Stage 2 → Stage 3 pipeline:
  1. Fetch actionable findings from Dependency-Track (Stage 1)
  2. Run reachability filter to get Stage 3 candidates (Stage 2)
  3. For each candidate, assemble code context (Stage 3 — zero tokens)
  4. [--analyze] Feed context to Claude to determine exploitability
  5. Record structured verdicts with generate_finding_verdict
  6. Generate a VEX report for CI/CD gating
  7. [--apply] Write verdicts back to Dependency-Track

Usage:
    # Show Stage 3 context without LLM analysis (dry-run):
    uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <path>

    # Full LLM analysis (requires ANTHROPIC_API_KEY env var):
    uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <path> --analyze

    # Analyze a single package (no DT required):
    uv run python scripts/poc_stage3.py --project-path <path> --package adm-zip \\
        --vuln-id CVE-2018-1002204 --severity HIGH \\
        --description "Path traversal in extractAllTo()" --analyze

    # Full pipeline with write-back to DT:
    uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <path> \\
        --analyze --apply
"""

import argparse
import asyncio
import json
import os

import anthropic
from fastmcp import Client

from zeronoise.server import mcp

_DIVIDER = "=" * 70


def _pretty(data: dict | list) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


def _section(title: str) -> None:
    print(f"\n{_DIVIDER}")
    print(f"  {title}")
    print(_DIVIDER)


# ── Stage 3 system prompt ─────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are ZeroNoise — a precision vulnerability auditor. Your job is to determine
whether a specific CVE is exploitable in a given codebase by examining only the
relevant code snippets provided.

Rules:
- Base your verdict ONLY on the provided code context. Do not assume or infer.
- Return a single JSON object with these exact fields:
    {
      "verdict": "<one of: NOT_REACHABLE | REACHABLE | LIKELY_EXPLOITABLE | EXPLOITABLE | FALSE_POSITIVE>",
      "justification": "<one of: CODE_NOT_REACHABLE | FEATURE_NOT_USED | SANITIZED_INPUT | AUTH_REQUIRED | PERMISSION_BOUNDARY | MITIGATING_CONTROL_PRESENT | NON_PRODUCTION_PATH>",
      "confidence": <float 0.0–1.0>,
      "confidence_reason": "<one sentence explaining confidence level>",
      "analysis": "<2–4 sentences explaining your verdict>",
      "requires_human_review": <true|false>
    }
- Confidence = 1.0 only when the evidence is unambiguous.
- If snippets are insufficient to decide, set verdict=REACHABLE and requires_human_review=true.
- NEVER return free text outside the JSON object.
"""


def _build_user_message(context: dict) -> str:
    finding = context["finding"]
    signals = context["pre_analysis_signals"]
    bundles = context["context_bundles"]
    instructions = context["analysis_instructions"]

    lines = [
        f"## Vulnerability: {finding['vulnerability_id']}",
        f"Package: {finding['package']}  |  Severity: {finding['severity']}  |  CVSS: {finding.get('cvss', 'N/A')}",
        f"Description: {finding['description']}",
        "",
        "## Pre-analysis signals",
        f"  Near user input: {signals['any_call_site_near_user_input']}",
        f"  Sanitization detected: {signals['any_sanitization_detected']}",
        f"  Vulnerable functions found in code: {signals['known_vulnerable_functions_found']}",
        f"  Risk signal: {signals['risk_signal']}",
        "",
        "## Code context bundles",
    ]

    for i, bundle in enumerate(bundles, start=1):
        lines.append(f"\n### Bundle {i}: {bundle['file']} (import line {bundle['import_line']})")
        lines.append(f"Import: `{bundle['import_statement']}`")
        if bundle["local_binding"]:
            lines.append(f"Bound as: `{bundle['local_binding']}`")

        lines.append("\nImport context:")
        for entry in bundle["import_context"]:
            lines.append(f"  {entry['line_no']:4d} | {entry['code']}")

        if bundle["vulnerable_function_calls"]:
            lines.append(f"\nCall sites ({bundle['call_site_count']} found):")
            for cs in bundle["vulnerable_function_calls"][:5]:
                lines.append(f"\n  ► {cs['function']}() at line {cs['line']}")
                lines.append(f"    Statement: {cs['statement']}")
                lines.append(f"    Near user input: {cs['analysis_hints']['near_user_input']} | "
                              f"Sanitization: {cs['analysis_hints']['sanitization_present']}")
                lines.append("    Context:")
                for entry in cs["context"]:
                    lines.append(f"      {entry['line_no']:4d} | {entry['code']}")
        else:
            lines.append("\n  (No call sites found for known vulnerable functions)")

    lines.append("\n## Analysis objective")
    lines.append(instructions["objective"])
    lines.append("\nCheck for:")
    for check in instructions["check_for"]:
        lines.append(f"  • {check}")

    return "\n".join(lines)


# ── Tool demos ────────────────────────────────────────────────────────────────

async def demo_prepare_context(
    client: Client,
    project_path: str,
    package: str,
    vuln_id: str,
    severity: str,
    description: str,
    vulnerable_functions: list[str],
    cvss: float | None,
) -> dict | None:
    _section(f"TOOL: prepare_stage3_context  [{package} / {vuln_id}]")
    result = await client.call_tool(
        "prepare_stage3_context",
        {
            "project_path": project_path,
            "package_name": package,
            "vulnerability_id": vuln_id,
            "severity": severity,
            "vulnerability_description": description,
            "vulnerable_functions": vulnerable_functions,
            "cvss": cvss,
        },
    )
    ctx = json.loads(result.content[0].text)

    if "error" in ctx:
        print(f"[!] {ctx['error']}")
        return None

    reach = ctx["reachability"]
    signals = ctx["pre_analysis_signals"]
    print(f"Package          : {ctx['finding']['package']}")
    print(f"Vulnerability    : {ctx['finding']['vulnerability_id']}  ({ctx['finding']['severity']})")
    print(f"Reachability     : {reach['verdict']}  (confidence {reach['confidence']:.2f})")
    print(f"Files w/ imports : {reach['files_with_imports']}")
    print(f"Call sites found : {reach['total_call_sites_found']}")
    print(f"\nPre-analysis signals:")
    print(f"  Near user input    : {signals['any_call_site_near_user_input']}")
    print(f"  Sanitization seen  : {signals['any_sanitization_detected']}")
    print(f"  Risk signal        : {signals['risk_signal']}")
    print(f"\nContext bundles    : {len(ctx['context_bundles'])}")
    for b in ctx["context_bundles"]:
        print(f"  {b['file']}  →  {b['call_site_count']} call site(s)")
    return ctx


async def demo_llm_analysis(context: dict) -> dict | None:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n[!] ANTHROPIC_API_KEY not set — skipping LLM analysis.")
        print("    Set it in your .env or environment to enable Stage 3 analysis.")
        return None

    _section("STAGE 3: LLM Contextual Analysis  [Claude]")
    print(f"Sending context to Claude for: {context['finding']['vulnerability_id']} ...")

    anthropic_client = anthropic.Anthropic(api_key=api_key)
    user_message = _build_user_message(context)

    response = anthropic_client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text.strip()
    # Extract JSON even if Claude wraps it in a code block
    if "```" in raw:
        raw = raw.split("```")[1].lstrip("json").strip()

    try:
        analysis = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[!] Could not parse LLM response as JSON:\n{raw}")
        return None

    print(f"\nVerdict          : {analysis.get('verdict')}")
    print(f"Justification    : {analysis.get('justification')}")
    print(f"Confidence       : {analysis.get('confidence')}  — {analysis.get('confidence_reason')}")
    print(f"Human review     : {analysis.get('requires_human_review')}")
    print(f"\nAnalysis:\n  {analysis.get('analysis')}")

    usage = response.usage
    print(f"\nTokens used      : {usage.input_tokens} in / {usage.output_tokens} out")
    return analysis


async def demo_generate_verdict(
    client: Client,
    finding_id: str,
    analysis: dict,
    context: dict,
) -> dict | None:
    _section(f"TOOL: generate_finding_verdict  [{finding_id}]")
    evidence = [
        u
        for b in context.get("context_bundles", [])
        for u in [{"file": b["file"], "line": b["import_line"],
                   "statement": b["import_statement"],
                   "matched_pattern": b["matched_pattern"], "reason": ""}]
    ]
    result = await client.call_tool(
        "generate_finding_verdict",
        {
            "finding_id": finding_id,
            "verdict": analysis["verdict"],
            "justification": analysis["justification"],
            "confidence": analysis["confidence"],
            "evidence": evidence,
            "analysis_details": analysis.get("analysis", ""),
        },
    )
    verdict_record = json.loads(result.content[0].text)
    gate = verdict_record.get("stage3_gate", {})
    print(f"Verdict          : {verdict_record['verdict']}")
    print(f"DT state         : {verdict_record['dt_analysis_state']}")
    print(f"Confidence       : {verdict_record['confidence']}")
    print(f"Stage 3 gate     : {gate.get('stage3_allowed')}  — {gate.get('reason')}")
    return verdict_record


async def demo_vex_report(client: Client, project_name: str, version: str, verdicts: list[dict]) -> None:
    _section("TOOL: generate_vex_report")
    findings_input = [
        {
            "vuln_id": v["finding_id"].split(":")[-1] if ":" in v["finding_id"] else v["finding_id"],
            "purl": "",
            "component": v["finding_id"],
            "verdict": v["verdict"],
            "justification": v["justification"],
            "analysis_details": v.get("analysis_details", ""),
            "confidence": v["confidence"],
            "evidence": v.get("evidence", []),
        }
        for v in verdicts
    ]
    result = await client.call_tool(
        "generate_vex_report",
        {"project_name": project_name, "project_version": version, "findings": findings_input},
    )
    vex = json.loads(result.content[0].text)
    summary = vex["summary"]
    print(f"Pipeline decision: {vex['pipeline_decision']}")
    print(f"Total            : {summary['total']}")
    print(f"  Affected       : {summary['affected']}")
    print(f"  Not affected   : {summary['not_affected']}")
    print(f"  Under review   : {summary['under_investigation']}")


# ── Full pipeline ─────────────────────────────────────────────────────────────

async def run_single_package(
    client: Client,
    project_path: str,
    package: str,
    vuln_id: str,
    severity: str,
    description: str,
    analyze: bool,
) -> None:
    ctx = await demo_prepare_context(
        client, project_path, package, vuln_id, severity, description, [], None
    )
    if ctx is None:
        return

    analysis = None
    if analyze:
        analysis = await demo_llm_analysis(ctx)

    if analysis:
        verdict = await demo_generate_verdict(client, f"single:{vuln_id}", analysis, ctx)
        if verdict:
            await demo_vex_report(client, package, "0.0.0", [verdict])


async def run_full_pipeline(
    client: Client,
    project_uuid: str,
    project_path: str,
    analyze: bool,
    apply: bool,
) -> None:
    # ── Stage 1: get actionable findings ──────────────────────────────────────
    _section("STAGE 1: Actionable Findings")
    s1_result = await client.call_tool("get_actionable_findings", {"project_uuid": project_uuid})
    s1_data = json.loads(s1_result.content[0].text)
    project_name = s1_data["project"]["name"]
    project_version = s1_data["project"].get("version", "unknown")
    print(f"Project          : {project_name} @ {project_version}")
    print(f"Actionable       : {s1_data['actionable_count']}")

    # ── Stage 2: reachability filter ─────────────────────────────────────────
    _section("STAGE 2: Reachability Filter")
    s2_result = await client.call_tool(
        "run_reachability_filter",
        {"project_uuid": project_uuid, "project_path": project_path, "dry_run": not apply},
    )
    s2_data = json.loads(s2_result.content[0].text)
    candidates = s2_data.get("stage3_candidates", [])
    print(f"Total actionable : {s2_data['total_actionable']}")
    print(f"NOT reachable    : {s2_data['not_reachable_count']}  → marked NOT_AFFECTED")
    print(f"Reachable        : {s2_data['reachable_count']}")
    print(f"Stage 3 eligible : {s2_data['stage3_candidates_count']}  (confidence >= {s2_data['stage3_confidence_threshold']})")
    print(f"Noise reduction  : {s2_data['noise_reduction_pct']}%")

    if apply:
        print(f"\n[{'APPLIED' if not s2_data['dry_run'] else 'DRY RUN'}] "
              f"NOT_AFFECTED verdicts written: {s2_data['not_reachable_count']}")

    if not candidates:
        print("\n[OK] No Stage 3 candidates — all findings resolved by Stage 2.")
        return

    print(f"\nStage 3 candidates:")
    for c in candidates:
        print(f"  {c['vuln_id']}  {c['component']}  "
              f"(confidence {c['confidence']:.2f}, {c['usage_count']} usage(s))")

    # ── Stage 3: contextual analysis ─────────────────────────────────────────
    # Deduplicate by component to avoid re-analyzing the same package multiple times
    seen_components: dict[str, dict] = {}
    for candidate in candidates:
        comp_name = candidate["component"].split("@")[0]
        if comp_name not in seen_components:
            seen_components[comp_name] = candidate

    # Fetch finding details to get vulnerability descriptions
    s1_findings = {
        f["finding_id"]: f
        for f in s1_data["findings"]
    }

    verdicts: list[dict] = []

    for candidate in candidates:
        finding = s1_findings.get(candidate["finding_id"], {})
        vuln = finding.get("vulnerability", {})

        ctx = await demo_prepare_context(
            client=client,
            project_path=project_path,
            package=candidate["component"].split("@")[0],
            vuln_id=candidate["vuln_id"],
            severity=vuln.get("severity", "UNKNOWN"),
            description=vuln.get("description") or "(no description available)",
            vulnerable_functions=[
                vf["function_name"]
                for vf in vuln.get("vulnerable_functions", [])
            ],
            cvss=vuln.get("cvss_v3_score"),
        )
        if ctx is None:
            continue

        analysis = None
        if analyze:
            analysis = await demo_llm_analysis(ctx)

        if analysis:
            verdict = await demo_generate_verdict(
                client, candidate["finding_id"], analysis, ctx
            )
            if verdict:
                verdicts.append(verdict)
                if apply and verdict["dt_analysis_state"] in {"NOT_AFFECTED", "FALSE_POSITIVE", "EXPLOITABLE"}:
                    await client.call_tool(
                        "update_finding_analysis",
                        {
                            "project_uuid": project_uuid,
                            "component_uuid": candidate["component_uuid"],
                            "vulnerability_uuid": candidate["vulnerability_uuid"],
                            "state": verdict["dt_analysis_state"],
                            "details": (
                                f"[ZeroNoise Stage 3] {verdict.get('analysis_details', '')} "
                                f"(confidence {verdict['confidence']:.2f})"
                            ),
                            "suppressed": False,
                        },
                    )
                    print(f"  → Written to DT: {verdict['dt_analysis_state']}")
        else:
            # No LLM analysis — create a REACHABLE placeholder verdict
            verdicts.append({
                "finding_id": candidate["finding_id"],
                "verdict": "REACHABLE",
                "justification": "CODE_NOT_REACHABLE",
                "confidence": candidate["confidence"],
                "analysis_details": "Requires LLM contextual analysis (--analyze not set)",
                "dt_analysis_state": "IN_TRIAGE",
                "evidence": [],
            })

    if verdicts:
        await demo_vex_report(client, project_name, project_version, verdicts)

    print(f"\n[OK] Stage 3 POC complete.  Verdicts: {len(verdicts)}")


# ── Entry point ───────────────────────────────────────────────────────────────

async def run(args: argparse.Namespace) -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()
        print(f"[MCP] {len(tools)} tools registered\n")

        if args.package:
            await run_single_package(
                client=client,
                project_path=args.project_path,
                package=args.package,
                vuln_id=args.vuln_id or "CVE-UNKNOWN",
                severity=args.severity or "HIGH",
                description=args.description or "(no description provided)",
                analyze=args.analyze,
            )
        elif args.project_uuid:
            await run_full_pipeline(
                client=client,
                project_uuid=args.project_uuid,
                project_path=args.project_path,
                analyze=args.analyze,
                apply=args.apply,
            )
        else:
            print("[!] Provide --project-uuid for the full pipeline, or --package for a single-package demo.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZeroNoise Stage 3 POC — Contextual LLM Analysis"
    )
    parser.add_argument("--project-uuid", help="Dependency-Track project UUID")
    parser.add_argument(
        "--project-path", required=True,
        help="Absolute path to the project source code on disk",
    )
    # Single-package mode
    parser.add_argument("--package", help="Single npm package to analyze (skips DT lookup)")
    parser.add_argument("--vuln-id", default="CVE-UNKNOWN", help="CVE or advisory ID")
    parser.add_argument("--severity", default="HIGH", help="Severity level")
    parser.add_argument("--description", default="", help="Vulnerability description")
    # Flags
    parser.add_argument(
        "--analyze", action="store_true", default=False,
        help="Call Claude API for LLM contextual analysis (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--apply", action="store_true", default=False,
        help="Write Stage 3 verdicts back to Dependency-Track",
    )
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
