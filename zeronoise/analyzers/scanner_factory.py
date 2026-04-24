"""
Scanner factory and language detection.

Provides a single entry point for selecting the right ImportScanner
implementation based on the package ecosystem and project structure.

Detection priority:
  1. PURL scheme     (pkg:maven/ → java, pkg:npm/ → javascript, ...)
  2. Project markers (pom.xml / build.gradle → java, package.json → javascript)
  3. Default         → javascript (preserves backward compatibility)
"""

from pathlib import Path

from zeronoise.analyzers.base_scanner import ImportScanner
from zeronoise.models.security_policy import SecurityPolicy, DEFAULT_POLICY

# Maps PURL scheme prefixes to language names
_PURL_SCHEME_MAP: dict[str, str] = {
    "pkg:maven/":  "java",
    "pkg:gradle/": "java",
    "pkg:npm/":    "javascript",
    "pkg:pypi/":   "python",
    "pkg:golang/": "go",
    "pkg:cargo/":  "rust",
}

# Project root markers that identify the language/build system
_PROJECT_MARKERS: list[tuple[str, str]] = [
    ("pom.xml",           "java"),
    ("build.gradle",      "java"),
    ("build.gradle.kts",  "java"),
    ("package.json",      "javascript"),
    ("setup.py",          "python"),
    ("pyproject.toml",    "python"),
    ("requirements.txt",  "python"),
    ("go.mod",            "go"),
    ("Cargo.toml",        "rust"),
]


def detect_language(project_path: str, package_name: str) -> str:
    """
    Detect the target programming language for a project/package pair.

    Args:
        project_path: Absolute path to the project root.
        package_name: Package name, PURL, or Maven GAV coordinate.

    Returns:
        Language string: "java" | "javascript" | "python" | "go" | "rust"
        Defaults to "javascript" when detection is ambiguous.
    """
    # 1. PURL-based detection (most reliable — ecosystem is explicit)
    pkg_lower = package_name.lower()
    for prefix, language in _PURL_SCHEME_MAP.items():
        if pkg_lower.startswith(prefix):
            return language

    # Maven GAV: groupId:artifactId[:version]
    if ":" in package_name and not package_name.startswith("pkg:"):
        # Maven GAV always has at least one colon; npm names never do
        # Heuristic: if it looks like a Java reverse-domain groupId
        group_id = package_name.split(":")[0].lower()
        java_group_prefixes = ("org.", "com.", "net.", "io.", "edu.", "gov.")
        if group_id.startswith(java_group_prefixes):
            return "java"

    # 2. Project marker detection (walk up from project_path)
    root = Path(project_path)
    for marker, language in _PROJECT_MARKERS:
        if (root / marker).exists():
            return language

    # 3. Default
    return "javascript"


def get_scanner(
    language: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> ImportScanner:
    """
    Return the ImportScanner implementation for the given language.

    Args:
        language: "java" | "javascript" (others will be added as scanners are implemented)
        policy: Security policy to enforce during scanning.
    """
    if language == "java":
        from zeronoise.analyzers.java_import_scanner import JavaImportScanner
        return JavaImportScanner(policy)

    # Default: JavaScript / TypeScript
    from zeronoise.analyzers.js_import_scanner import JsImportScanner
    return JsImportScanner(policy)


def get_scanner_auto(
    project_path: str,
    package_name: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> ImportScanner:
    """
    Convenience: detect language and return the matching scanner in one call.
    """
    language = detect_language(project_path, package_name)
    return get_scanner(language, policy)
