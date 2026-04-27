"""Shared input validation helpers for all ZeroNoise MCP tools."""

import re
from pathlib import Path

_UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

_VULN_ID_PATTERN = re.compile(
    r'^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$',
    re.IGNORECASE,
)

# PURLs include ':', '+', so both are allowed alongside the base charset
_PACKAGE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\-_/@.:+]{1,200}$')

_SHELL_CHARS_PATTERN = re.compile(r'[;&|`$]')

# Unix sensitive directories blocked even within a nominally valid project root
_SENSITIVE_DIR_PREFIXES = (
    '/etc/', '/root/', '/proc/', '/sys/', '/boot/',
    '/.ssh/', '/.aws/', '/.config/', '/.gnupg/',
)


def _validate_uuid(value: str, field: str) -> None:
    if not isinstance(value, str) or not _UUID_PATTERN.match(value):
        raise ValueError(f"{field} no es un UUID v4 válido: {value!r}")


def _validate_project_path(path: str) -> Path:
    if '\x00' in path:
        raise ValueError("project_path contiene null bytes")
    if '~' in path:
        raise ValueError("project_path no puede contener '~'")
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"project_path debe ser una ruta absoluta: {path!r}")
    if not p.exists():
        raise ValueError(f"project_path no existe: {path!r}")
    return p


def _validate_file_path(file_path: str) -> None:
    if not file_path:
        raise ValueError("file_path no puede estar vacío")
    if '\x00' in file_path:
        raise ValueError("file_path contiene null bytes")
    if '..' in file_path:
        raise ValueError(f"file_path contiene '..': {file_path!r}")
    if '~' in file_path:
        raise ValueError(f"file_path contiene '~': {file_path!r}")
    if _SHELL_CHARS_PATTERN.search(file_path):
        raise ValueError(
            f"file_path contiene caracteres de shell no permitidos: {file_path!r}"
        )
    norm = file_path.replace('\\', '/')
    for prefix in _SENSITIVE_DIR_PREFIXES:
        if norm.startswith(prefix):
            raise ValueError(
                f"file_path apunta a un directorio sensible del sistema: {file_path!r}"
            )


def _validate_package_name(name: str) -> None:
    if not name:
        raise ValueError("package_name no puede estar vacío")
    if not _PACKAGE_NAME_PATTERN.match(name):
        raise ValueError(
            f"package_name inválido: {name!r}. "
            "Solo alfanuméricos, '-', '_', '/', '@', '.', ':', '+' — máx 200 chars."
        )


def _validate_vulnerability_id(vuln_id: str) -> None:
    if not _VULN_ID_PATTERN.match(vuln_id):
        raise ValueError(
            f"vulnerability_id inválido: {vuln_id!r}. "
            "Debe tener formato CVE-YYYY-NNNNN o GHSA-xxxx-xxxx-xxxx."
        )


def _validate_line_numbers(start_line: int, end_line: int) -> None:
    if not (1 <= start_line <= 100_000):
        raise ValueError(f"start_line debe estar entre 1 y 100000, recibido: {start_line}")
    if not (1 <= end_line <= 100_000):
        raise ValueError(f"end_line debe estar entre 1 y 100000, recibido: {end_line}")
    if end_line < start_line:
        raise ValueError(
            f"end_line ({end_line}) debe ser mayor o igual a start_line ({start_line})"
        )
