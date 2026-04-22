"""
JavaScript / TypeScript static import scanner.

Detects whether a given npm package is imported anywhere in the project
source tree using regex-based AST-free analysis. Covers:
  - CommonJS:  require('pkg') / require("pkg")
  - ES Modules: import ... from 'pkg' / import('pkg') / export ... from 'pkg'
  - Scoped packages: @scope/pkg

Security policy enforced:
  - Skips disallowed directories (node_modules, .git, dist, build, etc.)
  - Skips files larger than max_file_size_bytes (default 1 MB)
  - Does not follow symbolic links
  - Respects max_scan_depth
"""

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from zeronoise.analyzers.base_scanner import ImportScanner
from zeronoise.models.reachability import ImportUsage, ReachabilityResult, ReproducibilityMetadata
from zeronoise.models.security_policy import SecurityPolicy, DEFAULT_POLICY

_ANALYZER_NAME = "js_import_scanner"
_ANALYZER_VERSION = "2.0.0"
_RULESET_VERSION = "2025-04"

_SOURCE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})

_LIMITATIONS = [
    "Regex-based analysis: dynamic imports via variable interpolation may not be detected",
    "Only JavaScript/TypeScript supported (.js, .mjs, .cjs, .ts, .tsx, .jsx)",
    "Symbolic links are not followed",
    "Re-exports through barrel files (index.js) are not traced transitively",
]

# Named patterns — the tuple key is used as ImportUsage.matched_pattern
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "require",
        re.compile(
            r"""require\s*\(\s*['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*\)"""
        ),
    ),
    (
        "import_from",
        re.compile(
            r"""(?:import|export)\s+[\s\S]*?from\s+['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*[;\n]?"""
        ),
    ),
    (
        "import_dynamic",
        re.compile(
            r"""import\s*\(\s*['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*\)"""
        ),
    ),
    (
        "import_side_effect",
        re.compile(
            r"""import\s+['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*[;\n]?"""
        ),
    ),
]


def _normalise_package_name(purl_or_name: str) -> str:
    """
    Accept either a plain name ('adm-zip') or a PURL ('pkg:npm/adm-zip@0.4.7')
    and return just the package name, lowercased.
    """
    name = purl_or_name
    if name.startswith("pkg:npm/"):
        name = name[len("pkg:npm/"):]
    name = name.split("@")[0]
    return name.lower()


def _source_files(root: Path, policy: SecurityPolicy) -> list[Path]:
    """
    Enumerate source files under root, respecting the security policy.

    Skips disallowed directories, symlinks (when follow_symlinks=False),
    oversized files, and paths deeper than max_scan_depth.
    """
    files: list[Path] = []
    disallowed = frozenset(policy.disallowed_paths)
    root_depth = len(root.parts)

    for path in root.rglob("*"):
        # Depth guard
        if len(path.parts) - root_depth > policy.max_scan_depth:
            continue
        # Symlink guard
        if not policy.follow_symlinks and path.is_symlink():
            continue
        # Disallowed directory guard
        if any(part in disallowed for part in path.parts):
            continue
        if path.suffix not in _SOURCE_EXTENSIONS or not path.is_file():
            continue
        # File size guard
        try:
            if path.stat().st_size > policy.max_file_size_bytes:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def _scan_file(
    path: Path, package_name: str, root: Path
) -> list[ImportUsage]:
    usages: list[ImportUsage] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return usages

    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern_name, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                imported = match.group("pkg").lower()
                top_level = (
                    "/".join(imported.split("/")[:2])
                    if imported.startswith("@")
                    else imported.split("/")[0]
                )
                if top_level == package_name:
                    rel_path = str(path.relative_to(root))
                    usages.append(
                        ImportUsage(
                            file=rel_path,
                            line=line_no,
                            statement=line.strip()[:120],
                            matched_pattern=pattern_name,
                            reason=(
                                f"Package '{package_name}' matched via "
                                f"{pattern_name} pattern on line {line_no} "
                                f"of {rel_path}"
                            ),
                        )
                    )
                    break  # one usage per line is enough
    return usages


def _compute_confidence(is_reachable: bool, files_scanned: int, usage_count: int) -> tuple[float, str]:
    """Heuristic confidence score for a reachability verdict."""
    if is_reachable:
        return 1.0, f"Direct import evidence found in {usage_count} location(s)"
    if files_scanned == 0:
        return 0.0, "No source files found — cannot assert absence of imports"
    if files_scanned >= 100:
        conf = 0.95
    elif files_scanned >= 50:
        conf = 0.90
    elif files_scanned >= 20:
        conf = 0.80
    elif files_scanned >= 5:
        conf = 0.70
    else:
        conf = 0.50
    return conf, f"No import found across {files_scanned} scanned file(s)"


def _fingerprint(project_path: str, package: str, files: list[Path]) -> str:
    payload = project_path + ":" + package + ":" + ":".join(str(f) for f in sorted(files))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def scan_project(
    project_path: str,
    package: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> ReachabilityResult:
    """
    Scan all JS/TS source files under project_path for imports of package.

    Args:
        project_path: Absolute path to the project root.
        package: Package name or PURL (e.g. 'adm-zip' or 'pkg:npm/adm-zip@0.4.7').
        policy: Security policy controlling traversal boundaries.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path is not a directory: {root}")

    package_name = _normalise_package_name(package)
    files = _source_files(root, policy)

    all_usages: list[ImportUsage] = []
    for f in files:
        all_usages.extend(_scan_file(f, package_name, root))

    is_reachable = bool(all_usages)
    confidence, confidence_reason = _compute_confidence(is_reachable, len(files), len(all_usages))

    reproducibility = ReproducibilityMetadata(
        analyzer_name=_ANALYZER_NAME,
        analyzer_version=_ANALYZER_VERSION,
        ruleset_version=_RULESET_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_fingerprint=_fingerprint(str(root), package_name, files),
    )

    return ReachabilityResult(
        package=package_name,
        project_path=str(root),
        is_reachable=is_reachable,
        files_scanned=len(files),
        usages=all_usages,
        confidence=confidence,
        confidence_reason=confidence_reason,
        limitations=list(_LIMITATIONS),
        requires_human_review=not is_reachable and confidence < 0.7,
        reproducibility=reproducibility,
    )


def build_import_graph(
    project_path: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> dict[str, list[str]]:
    """
    Build a map of {relative_file_path → [imported packages]} for the project.
    Only includes files that import at least one external package.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path is not a directory: {root}")

    graph: dict[str, list[str]] = {}
    for path in _source_files(root, policy):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        packages: set[str] = set()
        for _, pattern in _PATTERNS:
            for match in pattern.finditer(content):
                pkg = match.group("pkg").lower()
                top_level = (
                    "/".join(pkg.split("/")[:2])
                    if pkg.startswith("@")
                    else pkg.split("/")[0]
                )
                packages.add(top_level)

        if packages:
            rel = str(path.relative_to(root))
            graph[rel] = sorted(packages)

    return graph


class JsImportScanner(ImportScanner):
    """ImportScanner implementation for JavaScript and TypeScript projects."""

    @property
    def language(self) -> str:
        return "javascript"

    @property
    def supported_extensions(self) -> frozenset[str]:
        return _SOURCE_EXTENSIONS

    def scan_project(self, project_path: str, package: str) -> ReachabilityResult:
        return scan_project(project_path, package, self.policy)

    def build_import_graph(self, project_path: str) -> dict[str, list[str]]:
        return build_import_graph(project_path, self.policy)
