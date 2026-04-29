"""
artifact_inspector.py — Inspecciona el fat JAR compilado para verificar versiones reales.

Resuelve Brecha 1: versión reportada por dep-check != versión real empaquetada.

Limitaciones conocidas:
- Solo fat JARs (Spring Boot uber JARs). JARs thin no tienen deps internas.
- Requiere que el artefacto esté compilado (target/ o build/libs/).
- Shaded JARs pueden tener versiones incorrectas en el manifest.
- Si no hay artefacto: retorna UNVERIFIABLE y el flujo continúa sin interrumpirse.
"""
from __future__ import annotations

import re
import zipfile
import io
from enum import Enum
from pathlib import Path
from typing import Optional

from zeronoise.models.artifact_finding import (
    ArtifactVersion, VersionVerdict, VersionVerification,
)

# "thymeleaf-3.4.5.jar" → ("thymeleaf", "3.4.5")
# "netty-resolver-dns-4.1.128.Final.jar" → ("netty-resolver-dns", "4.1.128.Final")
_JAR_NAME_RE = re.compile(
    r'(?:.*/)?([a-zA-Z0-9._-]+?)-(\d[\d.]*(?:\.(?:Final|RELEASE|GA|RC\d+|Beta\d+|Alpha\d+))?)\.jar$',
    re.IGNORECASE,
)

_LIB_PREFIXES = ["BOOT-INF/lib/", "WEB-INF/lib/", "lib/"]

_QUALIFIER_RE = re.compile(r'\.(Final|RELEASE|GA|SP\d+)$', re.IGNORECASE)

# Rutas de búsqueda ordenadas por build tool — la primera es la canónica.
_SEARCH_PATHS_BY_TOOL: dict[str, list[str]] = {
    "maven":   ["target", "build/libs", "build/outputs", "out/artifacts"],
    "gradle":  ["build/libs", "build/outputs", "out/artifacts", "target"],
    "unknown": ["target", "build/libs", "build/outputs", "out/artifacts"],
}


class BuildTool(str, Enum):
    MAVEN   = "maven"
    GRADLE  = "gradle"
    UNKNOWN = "unknown"


class ArtifactInspector:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._jar_index: Optional[dict[str, ArtifactVersion]] = None
        self._build_tool: Optional[BuildTool] = None

    def detect_build_tool(self) -> BuildTool:
        """Detecta el build tool leyendo los marcadores en la raíz del proyecto."""
        if self._build_tool is not None:
            return self._build_tool

        root = self.project_path
        if (root / "pom.xml").exists():
            self._build_tool = BuildTool.MAVEN
        elif any((root / f).exists() for f in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")):
            self._build_tool = BuildTool.GRADLE
        else:
            self._build_tool = BuildTool.UNKNOWN

        return self._build_tool

    def find_artifact(self) -> Optional[Path]:
        """
        Busca el fat JAR más reciente. Busca también en subdirectorios del directorio
        canónico del build tool. Loggea un mensaje claro si no encuentra nada.
        """
        import logging
        logger = logging.getLogger("zeronoise.artifact")

        build_tool = self.detect_build_tool()
        search_paths = _SEARCH_PATHS_BY_TOOL[build_tool.value]

        candidates = []
        for search_dir in search_paths:
            d = self.project_path / search_dir
            if not d.exists():
                continue
            # Buscar en el directorio y un nivel de subdirectorios
            for pattern in ["*.jar", "**/*.jar"]:
                for p in d.glob(pattern):
                    if p.name.endswith("-plain.jar"):
                        continue
                    if p.name.endswith("-sources.jar"):
                        continue
                    if p.name.endswith("-javadoc.jar"):
                        continue
                    candidates.append(p)
            if candidates:
                break

        if not candidates:
            logger.info(
                f"No se encontró artefacto compilado en {self.project_path}. "
                f"Rutas buscadas: {search_paths}. "
                f"Para Gradle: ejecutar './gradlew build -x test' primero."
            )
            return None

        best = max(candidates, key=lambda p: p.stat().st_mtime)
        logger.info(f"Artefacto encontrado: {best}")
        return best

    def build_jar_index(self, artifact_path: Path) -> dict[str, ArtifactVersion]:
        """Construye índice {artifact_name_lower → ArtifactVersion}. Cacheable."""
        if self._jar_index is not None:
            return self._jar_index

        index: dict[str, ArtifactVersion] = {}
        if not zipfile.is_zipfile(artifact_path):
            self._jar_index = index
            return index

        try:
            with zipfile.ZipFile(artifact_path, "r") as zf:
                for entry in zf.namelist():
                    if not any(entry.startswith(p) for p in _LIB_PREFIXES):
                        continue
                    if not entry.endswith(".jar"):
                        continue
                    m = _JAR_NAME_RE.search(entry)
                    if not m:
                        continue
                    artifact_name = m.group(1)
                    version = m.group(2)
                    pom_version = self._read_pom_version(zf, entry)
                    if pom_version:
                        version = pom_version
                    av = ArtifactVersion(
                        artifact_name=artifact_name,
                        resolved_version=version,
                        source="pom_properties" if pom_version else "jar_filename",
                        jar_path=entry,
                    )
                    index[artifact_name.lower()] = av
        except (zipfile.BadZipFile, OSError):
            pass

        self._jar_index = index
        return index

    def verify_version(self, artifact_name: str, reported_version: str) -> VersionVerification:
        """Verifica si la versión reportada por dep-check coincide con la empaquetada."""
        build_tool = self.detect_build_tool()
        artifact_path = self.find_artifact()
        if artifact_path is None:
            expected_dir = _SEARCH_PATHS_BY_TOOL[build_tool.value][0]
            return VersionVerification(
                package_name=artifact_name,
                reported_version=reported_version,
                real_version=None,
                verdict=VersionVerdict.UNVERIFIABLE,
                analysis_note=(
                    f"No se encontró artefacto compilado en {self.project_path}. "
                    f"Build tool detectado: {build_tool.value}. "
                    f"Se esperaba el JAR en '{expected_dir}/'. "
                    f"Compilar el proyecto para habilitar verificación de versión."
                ),
            )

        index = self.build_jar_index(artifact_path)
        found = self._fuzzy_lookup(artifact_name.lower(), index)

        if found is None:
            return VersionVerification(
                package_name=artifact_name,
                reported_version=reported_version,
                real_version=None,
                verdict=VersionVerdict.NOT_FOUND,
                analysis_note=(
                    f"'{artifact_name}' no está empaquetado en {artifact_path.name}. "
                    f"Posible falso positivo — el JAR no está en el classpath runtime."
                ),
            )

        real = found.resolved_version
        verdict = (
            VersionVerdict.CONFIRMED
            if self._versions_equal(reported_version, real)
            else VersionVerdict.MISMATCH
        )
        note = ""
        if verdict == VersionVerdict.MISMATCH:
            note = (
                f"MISMATCH: dep-check reportó {artifact_name}@{reported_version} "
                f"pero el artefacto contiene {artifact_name}@{real}. "
                f"Usar {real} para evaluar el rango de versiones afectadas por el CVE."
            )
        return VersionVerification(
            package_name=artifact_name,
            reported_version=reported_version,
            real_version=real,
            verdict=verdict,
            found_in_artifact=found,
            analysis_note=note,
        )

    # ------------------------------------------------------------------
    def _read_pom_version(self, zf: zipfile.ZipFile, jar_entry: str) -> Optional[str]:
        try:
            inner_bytes = zf.read(jar_entry)
            with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
                for e in inner.namelist():
                    if "pom.properties" in e:
                        props = inner.read(e).decode("utf-8", errors="ignore")
                        for line in props.splitlines():
                            if line.startswith("version="):
                                return line.split("=", 1)[1].strip()
        except Exception:
            pass
        return None

    def _fuzzy_lookup(self, name: str, index: dict) -> Optional[ArtifactVersion]:
        if name in index:
            return index[name]
        for key, val in index.items():
            if key.startswith(name) or name.startswith(key):
                return val
        for key, val in index.items():
            if name in key or key in name:
                return val
        return None

    def _versions_equal(self, v1: str, v2: str) -> bool:
        return _QUALIFIER_RE.sub("", v1.strip()) == _QUALIFIER_RE.sub("", v2.strip())
