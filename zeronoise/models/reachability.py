from pydantic import BaseModel


class ImportUsage(BaseModel):
    file: str
    line: int
    statement: str


class ReachabilityResult(BaseModel):
    package: str
    project_path: str
    is_reachable: bool
    files_scanned: int
    usages: list[ImportUsage]

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
