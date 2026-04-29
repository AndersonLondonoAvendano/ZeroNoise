"""
project_context_reader.py — Lee documentación y configuración del proyecto.

Construye un contexto enriquecido para que el LLM en Stage 3 tenga información
del proyecto más allá del código fuente puro:
  - README.md / docs/*.md → arquitectura, propósito, entorno de despliegue
  - build.gradle / pom.xml → versiones declaradas, BOMs, exclusiones
  - application.yml / application.properties → perfil de exposición (¿es público?)
  - docker-compose.yml → contexto de red y exposición de puertos

El LLM usa este contexto para responder preguntas como:
  - ¿Este servicio está expuesto a internet o es interno?
  - ¿Qué versión de Spring Boot / framework usa?
  - ¿Hay exclusiones explícitas de módulos vulnerables?
  - ¿El BOM fuerza versiones específicas que resuelven el CVE?

LÍMITE: Máximo 2000 caracteres por archivo leído (para no saturar el contexto del LLM).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Archivos a buscar, en orden de prioridad
_CONTEXT_FILES = [
    # Documentación
    "README.md",
    "README.rst",
    "docs/README.md",
    "ARCHITECTURE.md",
    "docs/architecture.md",
    # Build y dependencias
    "build.gradle",
    "build.gradle.kts",
    "pom.xml",
    # Configuración de la app
    "src/main/resources/application.yml",
    "src/main/resources/application.yaml",
    "src/main/resources/application.properties",
    "src/main/resources/application-prod.yml",
    # Infraestructura
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
]

# Máximo de caracteres por archivo para no saturar el contexto del LLM
_MAX_CHARS_PER_FILE = 2000
_MAX_TOTAL_CHARS = 6000


@dataclass
class ProjectContext:
    """Contexto del proyecto para enriquecer el análisis de Stage 3."""

    project_path: str
    files_found: list[str] = field(default_factory=list)
    files_not_found: list[str] = field(default_factory=list)

    # Contenido relevante por archivo
    readme_summary: str = ""          # Primeros N chars del README
    build_config: str = ""            # build.gradle / pom.xml relevante
    app_config: str = ""              # application.yml / .properties
    infrastructure: str = ""         # docker-compose, Dockerfile

    # Datos extraídos automáticamente del build file
    spring_boot_version: Optional[str] = None
    java_version: Optional[str] = None
    excluded_modules: list[str] = field(default_factory=list)
    declared_boms: list[str] = field(default_factory=list)
    package_manager: str = "unknown"  # "gradle" | "maven" | "unknown"

    def to_llm_context(self) -> str:
        """
        Genera el string de contexto para pasar al LLM.
        Diseñado para ser incluido en el context bundle de Stage 3.
        """
        parts = []

        if self.spring_boot_version:
            parts.append(f"Spring Boot version: {self.spring_boot_version}")
        if self.java_version:
            parts.append(f"Java version: {self.java_version}")
        if self.package_manager != "unknown":
            parts.append(f"Build tool: {self.package_manager}")
        if self.declared_boms:
            parts.append(f"BOMs declarados: {', '.join(self.declared_boms)}")
        if self.excluded_modules:
            parts.append(f"Módulos excluidos explícitamente: {', '.join(self.excluded_modules)}")

        if self.readme_summary:
            parts.append(f"\n--- README ---\n{self.readme_summary}")
        if self.build_config:
            parts.append(f"\n--- Build config (extracto) ---\n{self.build_config}")
        if self.app_config:
            parts.append(f"\n--- App config (extracto) ---\n{self.app_config}")
        if self.infrastructure:
            parts.append(f"\n--- Infraestructura ---\n{self.infrastructure}")

        if not parts:
            return "Contexto del proyecto no disponible."

        return "\n".join(parts)


class ProjectContextReader:
    """
    Lee archivos de documentación y configuración del proyecto.

    Uso:
        reader = ProjectContextReader(project_path)
        context = reader.read()
        print(context.to_llm_context())
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)

    def read(self) -> ProjectContext:
        """Lee todos los archivos de contexto disponibles."""
        ctx = ProjectContext(project_path=str(self.project_path))

        # Detectar package manager
        if (self.project_path / "build.gradle").exists() or \
           (self.project_path / "build.gradle.kts").exists():
            ctx.package_manager = "gradle"
        elif (self.project_path / "pom.xml").exists():
            ctx.package_manager = "maven"

        total_chars = 0

        for relative_path in _CONTEXT_FILES:
            file_path = self.project_path / relative_path
            if not file_path.exists():
                ctx.files_not_found.append(relative_path)
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                truncated = content[:_MAX_CHARS_PER_FILE]
                ctx.files_found.append(relative_path)

                name = file_path.name.lower()
                if name in ("readme.md", "readme.rst", "architecture.md"):
                    ctx.readme_summary = truncated
                elif name in ("build.gradle", "build.gradle.kts", "pom.xml"):
                    ctx.build_config = truncated
                    self._parse_build_file(content, ctx)
                elif "application" in name:
                    ctx.app_config = truncated
                elif name in ("docker-compose.yml", "docker-compose.yaml", "dockerfile"):
                    ctx.infrastructure = truncated

                total_chars += len(truncated)
                if total_chars >= _MAX_TOTAL_CHARS:
                    break

            except Exception:
                pass

        return ctx

    def _parse_build_file(self, content: str, ctx: ProjectContext) -> None:
        """Extrae datos estructurados del build.gradle o pom.xml."""

        # Spring Boot version (Gradle plugin)
        sb_match = re.search(
            r"org\.springframework\.boot['\"]?\s+version\s+['\"]([^'\"]+)['\"]",
            content
        )
        if sb_match:
            ctx.spring_boot_version = sb_match.group(1)

        # Java version (Gradle toolchain)
        java_match = re.search(r"JavaLanguageVersion\.of\((\d+)\)", content)
        if java_match:
            ctx.java_version = java_match.group(1)

        # BOMs declarados
        bom_matches = re.findall(
            r'platform\(["\']([^"\']+:[^"\']+:[^"\']+)["\']',
            content
        )
        ctx.declared_boms.extend(bom_matches)

        # Exclusiones explícitas (Gradle)
        exclude_matches = re.findall(
            r"exclude\s+group:\s*['\"]([^'\"]+)['\"].*?module:\s*['\"]([^'\"]+)['\"]",
            content,
            re.DOTALL,
        )
        for group, module in exclude_matches:
            ctx.excluded_modules.append(f"{group}:{module}")

        # Maven: Spring Boot parent version
        if "<parent>" in content:
            parent_version = re.search(
                r"<parent>.*?<version>([^<]+)</version>.*?</parent>",
                content, re.DOTALL
            )
            if parent_version:
                ctx.spring_boot_version = parent_version.group(1)
