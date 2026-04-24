"""
Java static import scanner.

Detects whether a given Maven artifact is imported anywhere in a Java project
source tree. Handles:
  - Regular imports:  import com.fasterxml.jackson.databind.ObjectMapper;
  - Static imports:   import static org.springframework.util.Assert.notNull;
  - Wildcard imports: import org.apache.commons.lang3.*;

Package resolution (Maven → Java import prefix):
  - PURL:   pkg:maven/org.springframework/spring-core@5.3.0 → org.springframework
  - GAV:    org.springframework:spring-core:5.3.0          → org.springframework
  - GroupId: org.springframework                            → org.springframework
  - Legacy artifact IDs are resolved via known mapping table (commons-*, log4j, junit, etc.)

Typical project layout supported:
  project/
  ├── pom.xml | build.gradle
  └── src/
      ├── main/java/...  ← scanned
      └── test/java/...  ← scanned

Skipped: target/, build/, .gradle/, .idea/, out/, generated-sources/
"""

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from zeronoise.analyzers.base_scanner import ImportScanner
from zeronoise.models.reachability import ImportUsage, ReachabilityResult, ReproducibilityMetadata
from zeronoise.models.security_policy import SecurityPolicy, DEFAULT_POLICY

_ANALYZER_NAME = "java_import_scanner"
_ANALYZER_VERSION = "1.0.0"
_RULESET_VERSION = "2025-04"

_SOURCE_EXTENSIONS = frozenset({".java"})

_SKIP_DIRS = frozenset({
    "target",                  # Maven build output
    "build",                   # Gradle build output
    ".gradle",                 # Gradle cache
    ".idea",                   # IntelliJ project files
    "out",                     # IntelliJ output
    ".mvn",                    # Maven wrapper
    "generated-sources",       # APT / annotation processor output
    "generated-test-sources",
    ".git",
    ".cache",
    "__pycache__",
    "node_modules",
})

_LIMITATIONS = [
    "Regex-based analysis: reflection-based class loading (Class.forName) is not detected",
    "Only Java supported (.java files)",
    "Symbolic links are not followed",
    (
        "Legacy Maven artifacts with non-standard groupId→package mapping may produce "
        "false negatives (e.g. commons-collections → org.apache.commons.collections). "
        "Use the full PURL or groupId:artifactId for accurate resolution."
    ),
]

# Java import pattern — matches regular and static imports
# Captures the fully-qualified class/package name before the semicolon
_RE_IMPORT = re.compile(
    r"""^(?P<indent>[ \t]*)import\s+(?P<static>static\s+)?(?P<pkg>[a-zA-Z_\$][\w.\$]*(?:\.\*)?)\s*;""",
    re.MULTILINE,
)

# Known legacy Maven artifactIds / groupIds that do NOT match their Java package prefix
# Key: lowercase artifactId or groupId as it appears in Maven coordinates
# Value: the actual Java import prefix to search for
_LEGACY_IMPORT_MAPPINGS: dict[str, str] = {
    # Apache Commons (pre-2012 groupId was the artifactId itself)
    "commons-collections":       "org.apache.commons.collections",
    "commons-collections4":      "org.apache.commons.collections4",
    "commons-lang":              "org.apache.commons.lang",
    "commons-lang3":             "org.apache.commons.lang3",
    "commons-io":                "org.apache.commons.io",
    "commons-codec":             "org.apache.commons.codec",
    "commons-compress":          "org.apache.commons.compress",
    "commons-beanutils":         "org.apache.commons.beanutils",
    "commons-configuration":     "org.apache.commons.configuration",
    "commons-csv":               "org.apache.commons.csv",
    "commons-dbcp":              "org.apache.commons.dbcp",
    "commons-email":             "org.apache.commons.mail",
    "commons-fileupload":        "org.apache.commons.fileupload",
    "commons-math":              "org.apache.commons.math3",
    "commons-math3":             "org.apache.commons.math3",
    "commons-net":               "org.apache.commons.net",
    "commons-pool":              "org.apache.commons.pool",
    "commons-text":              "org.apache.commons.text",
    "commons-validator":         "org.apache.commons.validator",
    # Logging
    "log4j":                     "org.apache.log4j",
    "log4j-core":                "org.apache.logging.log4j",
    "log4j-api":                 "org.apache.logging.log4j",
    # Testing
    "junit":                     "org.junit",
    "junit-jupiter":             "org.junit.jupiter",
    "junit-jupiter-api":         "org.junit.jupiter.api",
    "junit-vintage-engine":      "org.junit.vintage",
    "mockito-core":              "org.mockito",
    "mockito-junit-jupiter":     "org.mockito",
    # Google
    "guava":                     "com.google.common",
    "gson":                      "com.google.gson",
    "protobuf-java":             "com.google.protobuf",
    # Other common mismatches
    "httpclient":                "org.apache.http",
    "httpclient5":               "org.apache.hc.client5",
    "httpcore":                  "org.apache.http.impl",
    "bcprov-jdk15on":            "org.bouncycastle",
    "bcprov-jdk18on":            "org.bouncycastle",
    "joda-time":                 "org.joda.time",
    "xstream":                   "com.thoughtworks.xstream",
    "velocity":                  "org.apache.velocity",
}


def _resolve_import_prefix(group_id: str) -> str:
    """
    Map a Maven groupId to its Java import prefix.

    For most modern packages (post-2005), groupId IS the Java package root.
    Legacy exceptions are handled via _LEGACY_IMPORT_MAPPINGS.
    """
    lower = group_id.lower()
    return _LEGACY_IMPORT_MAPPINGS.get(lower, lower)


def _normalise_package_name(purl_or_name: str) -> str:
    """
    Return the Java import prefix for a Maven artifact in any of these formats:

      pkg:maven/org.springframework/spring-core@5.3.0   → org.springframework
      org.springframework:spring-core:5.3.0              → org.springframework
      org.springframework:spring-core                    → org.springframework
      org.springframework                                → org.springframework
      spring-core  (legacy artifact name)                → spring-core (fallback)
    """
    name = purl_or_name.strip()

    # PURL format: pkg:maven/groupId/artifactId@version
    if name.startswith("pkg:maven/") or name.startswith("pkg:gradle/"):
        rest = re.sub(r"^pkg:[a-z]+/", "", name)
        rest = rest.split("@")[0]          # strip @version
        rest = rest.split("#")[0]          # strip qualifiers
        group_id = rest.split("/")[0]
        return _resolve_import_prefix(group_id)

    # GAV: groupId:artifactId[:version[:classifier]]
    if ":" in name:
        group_id = name.split(":")[0]
        return _resolve_import_prefix(group_id)

    # Check legacy artifactId mappings
    lower = name.lower()
    if lower in _LEGACY_IMPORT_MAPPINGS:
        return _LEGACY_IMPORT_MAPPINGS[lower]

    # Assume it's already a groupId / import prefix
    return lower


def _source_files(root: Path, policy: SecurityPolicy) -> list[Path]:
    files: list[Path] = []
    disallowed = frozenset(policy.disallowed_paths) | _SKIP_DIRS
    root_depth = len(root.parts)

    for path in root.rglob("*"):
        if len(path.parts) - root_depth > policy.max_scan_depth:
            continue
        if not policy.follow_symlinks and path.is_symlink():
            continue
        if any(part in disallowed for part in path.parts):
            continue
        if path.suffix not in _SOURCE_EXTENSIONS or not path.is_file():
            continue
        try:
            if path.stat().st_size > policy.max_file_size_bytes:
                continue
        except OSError:
            continue
        files.append(path)
    return files


def _scan_file(
    path: Path,
    import_prefix: str,
    root: Path,
) -> list[ImportUsage]:
    usages: list[ImportUsage] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return usages

    for match in _RE_IMPORT.finditer(content):
        pkg_raw = match.group("pkg")
        is_static = bool(match.group("static"))

        # Strip wildcard suffix for prefix comparison
        pkg_clean = pkg_raw.rstrip(".*").rstrip("*")

        # Match if the import starts with our prefix
        if pkg_clean == import_prefix or pkg_clean.startswith(import_prefix + "."):
            # Compute line number from character offset
            line_no = content[: match.start()].count("\n") + 1
            statement = match.group(0).strip()[:200]
            pattern_name = "import_static" if is_static else "import_wildcard" if pkg_raw.endswith("*") else "import"
            rel_path = str(path.relative_to(root))
            usages.append(
                ImportUsage(
                    file=rel_path,
                    line=line_no,
                    statement=statement,
                    matched_pattern=pattern_name,
                    reason=(
                        f"Package '{import_prefix}' matched via {pattern_name} "
                        f"on line {line_no} of {rel_path}"
                    ),
                )
            )

    return usages


def _compute_confidence(
    is_reachable: bool,
    files_scanned: int,
    usage_count: int,
) -> tuple[float, str]:
    if is_reachable:
        return 1.0, f"Direct import evidence found in {usage_count} location(s)"
    if files_scanned == 0:
        return 0.0, "No Java source files found — cannot assert absence of imports"
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
    return conf, f"No import found across {files_scanned} scanned .java file(s)"


def _fingerprint(project_path: str, package: str, files: list[Path]) -> str:
    payload = project_path + ":" + package + ":" + ":".join(str(f) for f in sorted(files))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def scan_project(
    project_path: str,
    package: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> ReachabilityResult:
    """
    Scan all .java files under project_path for imports of the given Maven artifact.

    Args:
        project_path: Absolute path to the Java project root.
        package: Maven artifact in any of: PURL, GAV, groupId, or artifactId.
        policy: Security policy controlling traversal boundaries.
    """
    root = Path(project_path).resolve()
    if not root.is_dir():
        raise ValueError(f"project_path is not a directory: {root}")

    import_prefix = _normalise_package_name(package)
    files = _source_files(root, policy)

    all_usages: list[ImportUsage] = []
    for f in files:
        all_usages.extend(_scan_file(f, import_prefix, root))

    is_reachable = bool(all_usages)
    confidence, confidence_reason = _compute_confidence(is_reachable, len(files), len(all_usages))

    reproducibility = ReproducibilityMetadata(
        analyzer_name=_ANALYZER_NAME,
        analyzer_version=_ANALYZER_VERSION,
        ruleset_version=_RULESET_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_fingerprint=_fingerprint(str(root), import_prefix, files),
    )

    return ReachabilityResult(
        package=import_prefix,
        project_path=str(root),
        is_reachable=is_reachable,
        files_scanned=len(files),
        usages=all_usages,
        confidence=confidence,
        confidence_reason=confidence_reason,
        limitations=list(_LIMITATIONS),
        requires_human_review=not is_reachable and confidence < 0.7,
        reproducibility=reproducibility,
        language="java",
    )


def build_import_graph(
    project_path: str,
    policy: SecurityPolicy = DEFAULT_POLICY,
) -> dict[str, list[str]]:
    """
    Build a map of {relative_file → [imported packages]} for the Java project.
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
        for match in _RE_IMPORT.finditer(content):
            pkg_raw = match.group("pkg").rstrip(".*").rstrip("*")
            # Use top-level 3-segment prefix as the "package" name
            # e.g. org.springframework.web.bind → org.springframework.web
            parts = pkg_raw.split(".")
            top = ".".join(parts[:3]) if len(parts) >= 3 else pkg_raw
            packages.add(top)

        if packages:
            rel = str(path.relative_to(root))
            graph[rel] = sorted(packages)

    return graph


class JavaImportScanner(ImportScanner):
    """ImportScanner implementation for Java/Maven projects."""

    @property
    def language(self) -> str:
        return "java"

    @property
    def supported_extensions(self) -> frozenset[str]:
        return _SOURCE_EXTENSIONS

    def scan_project(self, project_path: str, package: str) -> ReachabilityResult:
        return scan_project(project_path, package, self.policy)

    def build_import_graph(self, project_path: str) -> dict[str, list[str]]:
        return build_import_graph(project_path, self.policy)
