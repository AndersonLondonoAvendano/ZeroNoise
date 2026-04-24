"""
Stage 2.5 / Stage 3 — Code Context Tools

MCP tools that give the LLM surgical access to specific code fragments.
They NEVER load entire files; they always return bounded snippets.

Tool contracts:
  fetch_code_snippet      read_only: true  | side_effects: none | cost: low  | deterministic
  get_function_context    read_only: true  | side_effects: none | cost: low  | deterministic
  get_call_context        read_only: true  | side_effects: none | cost: low  | deterministic
  find_symbol_usages      read_only: true  | side_effects: none | cost: low  | heuristic

LLM Usage Policy (Section 11):
  - NEVER return more than max_snippet_lines lines per call
  - NEVER expose file contents outside the project root
  - Caller must provide evidence of reachability before using these tools
"""

import re
from pathlib import Path

from zeronoise.audit import audit_tool
from zeronoise.models.security_policy import DEFAULT_POLICY, SecurityPolicy

_POLICY = DEFAULT_POLICY


def _safe_resolve(project_path: str, relative_file: str) -> Path:
    """
    Resolve a user-supplied relative path against the project root.
    Raises ValueError if the result escapes the root (path traversal guard).
    """
    root = Path(project_path).resolve()
    target = (root / relative_file).resolve()
    if not str(target).startswith(str(root)):
        raise ValueError(f"Path traversal detected: {relative_file!r} escapes project root")
    return target


@audit_tool(side_effects="none")
async def fetch_code_snippet(
    project_path: str,
    file: str,
    start_line: int,
    end_line: int,
) -> dict:
    """
    Return specific lines from a source file within the project.

    The response is bounded by SecurityPolicy.max_snippet_lines to prevent
    the LLM from receiving more context than necessary.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_path: Absolute path to the project root on disk.
        file: Relative path to the source file within the project.
        start_line: First line to return (1-indexed, inclusive).
        end_line: Last line to return (1-indexed, inclusive).
    """
    max_lines = _POLICY.max_snippet_lines
    requested = end_line - start_line + 1
    if requested > max_lines:
        end_line = start_line + max_lines - 1

    target = _safe_resolve(project_path, file)
    if not target.is_file():
        return {"error": f"File not found: {file}"}

    if target.stat().st_size > _POLICY.max_file_size_bytes:
        return {"error": f"File exceeds max_file_size ({_POLICY.max_file_size_bytes} bytes): {file}"}

    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"error": str(exc)}

    total_lines = len(lines)
    start_line = max(1, start_line)
    end_line = min(total_lines, end_line)

    snippet = lines[start_line - 1: end_line]

    return {
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "truncated": requested > max_lines,
        "snippet": snippet,
    }


@audit_tool(side_effects="none")
async def get_function_context(
    project_path: str,
    file: str,
    function_name: str,
) -> dict:
    """
    Locate a function definition in a source file and return its body + surrounding context.

    Uses heuristic pattern matching for JS/TS function declarations,
    arrow functions, and method definitions.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: heuristic

    Args:
        project_path: Absolute path to the project root.
        file: Relative path to the source file.
        function_name: Name of the function or method to locate.
    """
    target = _safe_resolve(project_path, file)
    if not target.is_file():
        return {"error": f"File not found: {file}"}
    if target.stat().st_size > _POLICY.max_file_size_bytes:
        return {"error": f"File too large: {file}"}

    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"error": str(exc)}

    # Language detection from file extension
    is_java = target.suffix == ".java"

    if is_java:
        # Java: method declarations with any combination of modifiers
        # public/private/protected [static] [final] [synchronized] ReturnType methodName(
        fn_pattern = re.compile(
            rf"""(?:(?:public|private|protected|static|final|synchronized|abstract|native|default)\s+)*"""
            rf"""[\w\[\]<>,\s]+\s+{re.escape(function_name)}\s*\("""
        )
    else:
        # JavaScript / TypeScript
        fn_pattern = re.compile(
            rf"""(?:function\s+{re.escape(function_name)}\s*\(|"""
            rf"""(?:const|let|var)\s+{re.escape(function_name)}\s*=\s*(?:async\s*)?\(|"""
            rf"""{re.escape(function_name)}\s*[:(]\s*(?:async\s*)?\()"""
        )

    matches: list[dict] = []
    for line_no, line in enumerate(lines, start=1):
        if fn_pattern.search(line):
            ctx_start = max(1, line_no - 2)
            ctx_end = min(len(lines), line_no + _POLICY.max_snippet_lines - 3)
            matches.append({
                "definition_line": line_no,
                "context_start": ctx_start,
                "context_end": ctx_end,
                "snippet": lines[ctx_start - 1: ctx_end],
            })
            if len(matches) >= 3:  # return at most 3 definitions
                break

    if not matches:
        return {
            "file": file,
            "function_name": function_name,
            "found": False,
            "matches": [],
        }

    return {
        "file": file,
        "function_name": function_name,
        "found": True,
        "matches": matches,
        "limitations": [
            "Heuristic regex matching: may miss minified code or unusual formatting",
            "Does not resolve function aliases or re-exports",
        ],
    }


@audit_tool(side_effects="none")
async def get_call_context(
    project_path: str,
    file: str,
    function_name: str,
) -> dict:
    """
    Find all call sites of a function within a specific file.

    Returns each call site with surrounding context lines so the LLM can
    evaluate whether arguments are user-controlled or sanitized.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: heuristic

    Args:
        project_path: Absolute path to the project root.
        file: Relative path to the source file.
        function_name: Name of the function whose calls to find.
    """
    target = _safe_resolve(project_path, file)
    if not target.is_file():
        return {"error": f"File not found: {file}"}
    if target.stat().st_size > _POLICY.max_file_size_bytes:
        return {"error": f"File too large: {file}"}

    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return {"error": str(exc)}

    call_pattern = re.compile(rf"""\b{re.escape(function_name)}\s*\(""")
    context_radius = 3
    call_sites: list[dict] = []

    for line_no, line in enumerate(lines, start=1):
        if call_pattern.search(line):
            ctx_start = max(1, line_no - context_radius)
            ctx_end = min(len(lines), line_no + context_radius)
            call_sites.append({
                "line": line_no,
                "statement": line.strip()[:200],
                "context_start": ctx_start,
                "context_end": ctx_end,
                "context": lines[ctx_start - 1: ctx_end],
            })
            if len(call_sites) >= 20:  # cap to avoid flooding the LLM
                break

    return {
        "file": file,
        "function_name": function_name,
        "call_site_count": len(call_sites),
        "call_sites": call_sites,
        "limitations": ["Regex-based: may include false positives in string literals or comments"],
    }


@audit_tool(side_effects="none")
async def find_symbol_usages(
    project_path: str,
    symbol_name: str,
    file_extension: str = "",
) -> dict:
    """
    Search all source files in the project for usages of a symbol.

    Useful for Stage 3 to understand the blast radius of a vulnerable function
    before performing deep contextual analysis.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: heuristic

    Args:
        project_path: Absolute path to the project root.
        symbol_name: Function, class, or variable name to search for.
        file_extension: Optional filter (e.g. '.ts', '.java'). Empty = all source files
                        detected by the language-appropriate scanner.
    """
    from zeronoise.analyzers.scanner_factory import detect_language, get_scanner
    from zeronoise.models.security_policy import DEFAULT_POLICY

    root = Path(project_path).resolve()
    if not root.is_dir():
        return {"error": f"project_path is not a directory: {project_path}"}

    # Use the language-appropriate scanner to enumerate source files
    language = detect_language(project_path, "")
    scanner = get_scanner(language, DEFAULT_POLICY)

    # Access internal _source_files via the scanner's module
    if language == "java":
        from zeronoise.analyzers.java_import_scanner import _source_files
    else:
        from zeronoise.analyzers.js_import_scanner import _source_files

    files = _source_files(root, DEFAULT_POLICY)
    if file_extension:
        files = [f for f in files if f.suffix == file_extension]

    symbol_pattern = re.compile(rf"""\b{re.escape(symbol_name)}\b""")
    usages: list[dict] = []

    for path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(content.splitlines(), start=1):
            if symbol_pattern.search(line):
                usages.append({
                    "file": str(path.relative_to(root)),
                    "line": line_no,
                    "statement": line.strip()[:200],
                })
                if len(usages) >= 100:  # hard cap to protect LLM context
                    break
        if len(usages) >= 100:
            break

    return {
        "symbol_name": symbol_name,
        "files_searched": len(files),
        "usage_count": len(usages),
        "capped": len(usages) >= 100,
        "usages": usages,
        "limitations": [
            "Regex word-boundary matching: may include false positives",
            "Capped at 100 results — full list may be longer",
        ],
    }
