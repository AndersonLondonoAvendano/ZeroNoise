from pydantic import BaseModel, Field


class SecurityPolicy(BaseModel):
    """
    Server-level execution boundaries for all file-system operations.

    Enforced by scanners and code-context tools to prevent accidental
    access to secrets, build artifacts, or out-of-scope directories.
    """
    disallowed_paths: list[str] = Field(
        default_factory=lambda: [
            "node_modules", ".git", "dist", "build",
            "coverage", ".next", "out", ".venv", "__pycache__", ".cache",
        ],
        description="Directory names that are never scanned",
    )
    max_file_size_bytes: int = Field(
        default=1_048_576,  # 1 MB
        description="Files larger than this are skipped",
    )
    max_scan_depth: int = Field(
        default=20,
        description="Maximum directory depth to recurse",
    )
    follow_symlinks: bool = Field(
        default=False,
        description="Whether to follow symbolic links during traversal",
    )
    max_snippet_lines: int = Field(
        default=50,
        description="Maximum lines returned by fetch_code_snippet",
    )


# Singleton default policy — used by all scanners unless overridden
DEFAULT_POLICY = SecurityPolicy()
