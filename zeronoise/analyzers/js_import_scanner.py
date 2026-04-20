"""
JavaScript / TypeScript static import scanner.

Detects whether a given npm package is imported anywhere in the project
source tree using regex-based AST-free analysis. Covers:
  - CommonJS:  require('pkg') / require("pkg")
  - ES Modules: import ... from 'pkg' / import('pkg') / export ... from 'pkg'
  - Scoped packages: @scope/pkg

Intentionally skips: node_modules, .git, dist, build, coverage, .next, out.
"""

import re
from pathlib import Path

from zeronoise.models.reachability import ImportUsage, ReachabilityResult

# Directories that are never application source code
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        "coverage",
        ".next",
        "out",
        ".venv",
        "__pycache__",
        ".cache",
    }
)

_SOURCE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})

# CommonJS: require('pkg') or require("pkg")
_RE_REQUIRE = re.compile(
    r"""require\s*\(\s*['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*\)"""
)

# ES module static: import ... from 'pkg' / export ... from 'pkg'
_RE_IMPORT_FROM = re.compile(
    r"""(?:import|export)\s+[\s\S]*?from\s+['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*[;\n]?"""
)

# ES module dynamic: import('pkg')
_RE_IMPORT_DYNAMIC = re.compile(
    r"""import\s*\(\s*['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*\)"""
)

# Side-effect only: import 'pkg'
_RE_IMPORT_SIDE_EFFECT = re.compile(
    r"""import\s+['"](?P<pkg>@?[a-zA-Z0-9][\w.-]*(?:/[\w.-]+)?)['"]\s*[;\n]?"""
)

_ALL_PATTERNS = [_RE_REQUIRE, _RE_IMPORT_FROM, _RE_IMPORT_DYNAMIC, _RE_IMPORT_SIDE_EFFECT]


def _normalise_package_name(purl_or_name: str) -> str:
    """
    Accept either a plain name ('adm-zip') or a PURL ('pkg:npm/adm-zip@0.4.7')
    and return just the package name, lowercased.
    """
    name = purl_or_name
    if name.startswith("pkg:npm/"):
        name = name[len("pkg:npm/"):]
    name = name.split("@")[0]  # strip version
    return name.lower()


def _source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in _SOURCE_EXTENSIONS and path.is_file():
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
        for pattern in _ALL_PATTERNS:
            for match in pattern.finditer(line):
                imported = match.group("pkg").lower()
                # Match exact package or scoped sub-path (@scope/pkg/sub → @scope/pkg)
                top_level = "/".join(imported.split("/")[:2]) if imported.startswith("@") else imported.split("/")[0]
                if top_level == package_name:
                    usages.append(
                        ImportUsage(
                            file=str(path.relative_to(root)),
                            line=line_no,
                            statement=line.strip()[:120],
                        )
                    )
                    break  # one usage per line is enough
    return usages


def scan_project(project_path: str, package: str) -> ReachabilityResult:
    """
    Scan all JS/TS source files under `project_path` for imports of `package`.

    Args:
        project_path: Absolute path to the project root.
        package: Package name or PURL (e.g. 'adm-zip' or 'pkg:npm/adm-zip@0.4.7').
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path is not a directory: {root}")

    package_name = _normalise_package_name(package)
    files = _source_files(root)

    all_usages: list[ImportUsage] = []
    for f in files:
        all_usages.extend(_scan_file(f, package_name, root))

    return ReachabilityResult(
        package=package_name,
        project_path=str(root),
        is_reachable=bool(all_usages),
        files_scanned=len(files),
        usages=all_usages,
    )


def build_import_graph(project_path: str) -> dict[str, list[str]]:
    """
    Build a map of {relative_file_path → [imported packages]} for the project.
    Only includes files that import at least one external package.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path is not a directory: {root}")

    graph: dict[str, list[str]] = {}
    for path in _source_files(root):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        packages: set[str] = set()
        for pattern in _ALL_PATTERNS:
            for match in pattern.finditer(content):
                pkg = match.group("pkg").lower()
                top_level = "/".join(pkg.split("/")[:2]) if pkg.startswith("@") else pkg.split("/")[0]
                packages.add(top_level)

        if packages:
            rel = str(path.relative_to(root))
            graph[rel] = sorted(packages)

    return graph
