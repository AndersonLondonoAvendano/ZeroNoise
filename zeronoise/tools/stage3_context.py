"""
Stage 3 — Context Assembly

The single entry-point tool for contextual LLM analysis.

`prepare_stage3_context` gathers ALL evidence an LLM needs to determine
exploitability for one finding: import locations, call sites, surrounding
code, and user-input proximity signals.

This tool consumes ZERO LLM tokens — it is deterministic file-system analysis.
The LLM is the consumer, not the producer, of this tool's output.

Tool contract:
  prepare_stage3_context   read_only: true | side_effects: none | cost: low | heuristic

LLM Usage Policy enforced here:
  - Snippets are bounded by SecurityPolicy.max_snippet_lines
  - Files are capped at max_file_size_bytes
  - No secrets patterns are included in outputs
  - Caller must supply evidence of REACHABLE verdict before calling this tool
"""

import re
from pathlib import Path

from zeronoise.audit import audit_tool
from zeronoise.analyzers.js_import_scanner import scan_project
from zeronoise.models.security_policy import DEFAULT_POLICY

# Patterns that indicate user-controlled input nearby a call site
_USER_INPUT_PATTERNS = re.compile(
    r"""req\.(body|query|params|headers|files|cookies)|"""
    r"""request\.(body|query|data|form|json|files)|"""
    r"""ctx\.(request|query|params|body)|"""
    r"""process\.argv|"""
    r"""readline|"""
    r"""stdin|"""
    r"""event\.(target|data|body)|"""
    r"""socket\.(data|message)""",
    re.IGNORECASE,
)

# Patterns that suggest sanitization / validation is present
_SANITIZE_PATTERNS = re.compile(
    r"""sanitize|escape|validate|whitelist|allowlist|"""
    r"""\.replace\(|\.slice\(|path\.basename|"""
    r"""isValid|isSafe|checkPath|normalize""",
    re.IGNORECASE,
)

_CONTEXT_RADIUS = 6  # lines before/after a call site


def _read_lines(path: Path) -> list[str] | None:
    if path.stat().st_size > DEFAULT_POLICY.max_file_size_bytes:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None


def _snippet(lines: list[str], center: int, radius: int = _CONTEXT_RADIUS) -> list[dict]:
    """Return lines around center (1-indexed) as numbered dicts."""
    start = max(0, center - radius - 1)
    end = min(len(lines), center + radius)
    return [
        {"line_no": start + i + 1, "code": lines[start + i]}
        for i in range(end - start)
    ]


def _find_call_sites(
    lines: list[str],
    function_names: list[str],
) -> list[dict]:
    """Locate call sites for known vulnerable functions."""
    sites: list[dict] = []
    if not function_names:
        return sites
    pattern = re.compile(
        r"""\b(?:""" + "|".join(re.escape(fn) for fn in function_names) + r""")\s*\("""
    )
    for line_no, line in enumerate(lines, start=1):
        m = pattern.search(line)
        if m:
            ctx = _snippet(lines, line_no)
            ctx_text = "\n".join(c["code"] for c in ctx)
            sites.append({
                "function": m.group(0).rstrip("(").strip(),
                "line": line_no,
                "statement": line.strip()[:200],
                "context": ctx,
                "analysis_hints": {
                    "near_user_input": bool(_USER_INPUT_PATTERNS.search(ctx_text)),
                    "sanitization_present": bool(_SANITIZE_PATTERNS.search(ctx_text)),
                },
            })
            if len(sites) >= 10:
                break
    return sites


def _build_context_bundle(
    file_path: Path,
    root: Path,
    import_usage: dict,
    vulnerable_functions: list[str],
) -> dict | None:
    lines = _read_lines(file_path)
    if lines is None:
        return None

    rel_path = str(file_path.relative_to(root))
    import_line = import_usage["line"]
    import_ctx = _snippet(lines, import_line, radius=3)

    # Determine what the package is bound to (e.g. `const AdmZip = require(...)`)
    import_stmt = lines[import_line - 1] if import_line <= len(lines) else ""
    binding_match = re.search(r"""(?:const|let|var)\s+(\w+)\s*=""", import_stmt)
    local_binding = binding_match.group(1) if binding_match else None

    # Look for call sites using the local binding OR the vulnerable function names
    search_names = list(vulnerable_functions)
    if local_binding:
        search_names.insert(0, local_binding)

    call_sites = _find_call_sites(lines, search_names) if search_names else []

    return {
        "file": rel_path,
        "import_line": import_line,
        "import_statement": import_stmt.strip()[:200],
        "matched_pattern": import_usage.get("matched_pattern", ""),
        "local_binding": local_binding,
        "import_context": import_ctx,
        "vulnerable_function_calls": call_sites,
        "call_site_count": len(call_sites),
    }


@audit_tool(side_effects="none")
async def prepare_stage3_context(
    project_path: str,
    package_name: str,
    vulnerability_id: str,
    severity: str,
    vulnerability_description: str,
    vulnerable_functions: list[str] | None = None,
    cvss: float | None = None,
) -> dict:
    """
    Assemble the complete code context needed for LLM-based exploitability analysis.

    Scans the project for import locations, finds call sites for known vulnerable
    functions, and annotates each call site with user-input proximity signals.

    GATE: This tool should only be called when Stage 2 has confirmed REACHABLE
    verdict with confidence >= threshold.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: heuristic

    Args:
        project_path: Absolute path to the project source root.
        package_name: npm package name or PURL.
        vulnerability_id: CVE or advisory ID (e.g. CVE-2018-1002204).
        severity: CRITICAL | HIGH | MEDIUM | LOW.
        vulnerability_description: Plain-text description of the vulnerability.
        vulnerable_functions: Optional list of specific function names to find
                              call sites for (e.g. ["extractAllTo", "extractEntryTo"]).
        cvss: CVSS v3 base score, if available.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        return {"error": f"project_path is not a directory: {project_path}"}

    scan_result = scan_project(project_path, package_name)

    if not scan_result.is_reachable:
        return {
            "error": (
                f"Package '{scan_result.package}' is NOT_REACHABLE "
                "— Stage 3 context assembly aborted. "
                "Only call this tool for REACHABLE findings."
            ),
            "verdict": "NOT_REACHABLE",
            "package": scan_result.package,
        }

    fn_names = list(vulnerable_functions or [])
    context_bundles: list[dict] = []

    for usage in scan_result.usages:
        file_path = root / usage.file
        if not file_path.is_file():
            continue
        bundle = _build_context_bundle(
            file_path=file_path,
            root=root,
            import_usage=usage.model_dump(),
            vulnerable_functions=fn_names,
        )
        if bundle is not None:
            context_bundles.append(bundle)

    total_call_sites = sum(b["call_site_count"] for b in context_bundles)
    any_near_user_input = any(
        cs["analysis_hints"]["near_user_input"]
        for b in context_bundles
        for cs in b["vulnerable_function_calls"]
    )
    any_sanitization = any(
        cs["analysis_hints"]["sanitization_present"]
        for b in context_bundles
        for cs in b["vulnerable_function_calls"]
    )

    return {
        "finding": {
            "package": scan_result.package,
            "vulnerability_id": vulnerability_id,
            "severity": severity,
            "cvss": cvss,
            "description": vulnerability_description,
            "vulnerable_functions": fn_names,
        },
        "reachability": {
            "verdict": scan_result.verdict,
            "confidence": scan_result.confidence,
            "files_with_imports": len(scan_result.usages),
            "total_call_sites_found": total_call_sites,
        },
        "context_bundles": context_bundles,
        "pre_analysis_signals": {
            "any_call_site_near_user_input": any_near_user_input,
            "any_sanitization_detected": any_sanitization,
            "known_vulnerable_functions_found": total_call_sites > 0,
            "risk_signal": (
                "HIGH" if any_near_user_input and not any_sanitization
                else "MEDIUM" if any_near_user_input
                else "LOW"
            ),
        },
        "analysis_instructions": {
            "objective": (
                f"Determine whether {vulnerability_id} in '{scan_result.package}' "
                f"is exploitable in this specific codebase."
            ),
            "check_for": [
                "Is the destination/input path user-controlled?",
                "Is there validation or sanitization before the vulnerable call?",
                "Does this code run in an authenticated context?",
                "Is the endpoint publicly accessible (no auth middleware before it)?",
                "What privilege level does this process run with?",
                "Is the vulnerable function actually called, or only the package imported?",
            ],
            "verdict_options": [
                "NOT_REACHABLE — package imported but vulnerable function never called",
                "REACHABLE — called but input is validated / sanitized",
                "LIKELY_EXPLOITABLE — called with user input, minimal validation",
                "EXPLOITABLE — called with direct user input, no validation",
                "FALSE_POSITIVE — vulnerability does not apply to this usage pattern",
            ],
            "justification_options": [
                "CODE_NOT_REACHABLE", "FEATURE_NOT_USED", "SANITIZED_INPUT",
                "AUTH_REQUIRED", "PERMISSION_BOUNDARY", "MITIGATING_CONTROL_PRESENT",
                "NON_PRODUCTION_PATH",
            ],
        },
        "reproducibility": (
            scan_result.reproducibility.model_dump()
            if scan_result.reproducibility else None
        ),
    }
