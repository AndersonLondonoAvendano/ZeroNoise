from pydantic import BaseModel, Field


class ImportUsage(BaseModel):
    file: str
    line: int
    statement: str
    matched_pattern: str = Field(
        default="",
        description="Name of the regex pattern that matched (require | import_from | import_dynamic | import_side_effect)",
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of why this usage was flagged",
    )


class ReproducibilityMetadata(BaseModel):
    """Fingerprint that allows audit systems to reproduce or compare analysis runs."""
    analyzer_name: str
    analyzer_version: str
    ruleset_version: str
    timestamp: str  # ISO 8601
    input_fingerprint: str  # sha256 of (project_path + package + file list)


class ReachabilityResult(BaseModel):
    package: str
    project_path: str
    is_reachable: bool
    files_scanned: int
    usages: list[ImportUsage]
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_reason: str = ""
    limitations: list[str] = Field(default_factory=list)
    requires_human_review: bool = False
    reproducibility: ReproducibilityMetadata | None = None
    language: str = Field(default="javascript", description="Scanner language: javascript | java | python | go")

    @property
    def verdict(self) -> str:
        return "REACHABLE" if self.is_reachable else "NOT_REACHABLE"

    @property
    def dt_analysis_state(self) -> str:
        """Maps verdict to the Dependency-Track analysis state value."""
        return "NOT_AFFECTED" if not self.is_reachable else "IN_TRIAGE"

    @property
    def auto_justification(self) -> str:
        if not self.is_reachable:
            return (
                f"[ZeroNoise Stage 2] Package '{self.package}' is installed as a "
                f"dependency but is never imported or required by any application "
                f"source file ({self.files_scanned} files scanned). "
                "Marked NOT_AFFECTED — not reachable from application code."
            )
        files = ", ".join(u.file for u in self.usages[:3])
        extra = f" (+{len(self.usages) - 3} more)" if len(self.usages) > 3 else ""
        return (
            f"[ZeroNoise Stage 2] Package '{self.package}' is imported in "
            f"{len(self.usages)} file(s): {files}{extra}. "
            "Requires Stage 3 contextual analysis."
        )
