"""
Abstract base class for language-specific import scanners.

Each language implementation must fulfill this interface so that Stage 2
reachability analysis can be extended to Python, Java, Go, etc. without
modifying the calling tools.

Implementations:
  - JavaScript / TypeScript → js_import_scanner.JsImportScanner
  - Python                  → (pending) py_import_scanner.PyImportScanner
  - Java                    → (pending) java_import_scanner.JavaImportScanner
  - Go                      → (pending) go_import_scanner.GoImportScanner
"""

from abc import ABC, abstractmethod

from zeronoise.models.reachability import ReachabilityResult
from zeronoise.models.security_policy import SecurityPolicy, DEFAULT_POLICY


class ImportScanner(ABC):
    """
    Language-agnostic contract for static import analysis.

    Subclasses detect whether a given package is imported by the project
    source code using language-specific syntax rules.
    """

    def __init__(self, policy: SecurityPolicy = DEFAULT_POLICY) -> None:
        self.policy = policy

    @property
    @abstractmethod
    def language(self) -> str:
        """Human-readable language name, e.g. 'javascript'."""

    @property
    @abstractmethod
    def supported_extensions(self) -> frozenset[str]:
        """File extensions this scanner handles, e.g. frozenset({'.js', '.ts'})."""

    @abstractmethod
    def scan_project(self, project_path: str, package: str) -> ReachabilityResult:
        """
        Scan all source files under project_path for imports of package.

        Args:
            project_path: Absolute path to the project root on disk.
            package: Package name or ecosystem PURL (e.g. 'adm-zip').

        Returns:
            ReachabilityResult with verdict, confidence, evidence, and
            reproducibility metadata.
        """

    @abstractmethod
    def build_import_graph(self, project_path: str) -> dict[str, list[str]]:
        """
        Return a map of {relative_file → [imported packages]} for the project.

        Only files that import at least one external package are included.
        """
