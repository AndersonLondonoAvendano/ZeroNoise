# Tarea 03 — B1+B2: Inspector de artefacto JAR

**Archivo a crear:** `zeronoise/analyzers/artifact_inspector.py`
**Tiempo estimado:** 20 minutos
**Dependencias:** Tarea 02 implementada (`models/artifact_finding.py` existe)

---

## Problema

dep-check puede reportar `thymeleaf@3.4.6` pero el fat JAR compilado puede contener
`thymeleaf@3.4.5`. ZeroNoise emite veredictos basados en la versión reportada,
no en la versión real empaquetada.

## Crear `zeronoise/analyzers/artifact_inspector.py`

```python
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
from pathlib import Path
from typing import Optional

from zeronoise.models.artifact_finding import (
    ArtifactVersion, VersionVerdict, VersionVerification,
)

_ARTIFACT_SEARCH_PATHS = ["target", "build/libs", "build/outputs", "out/artifacts"]

# "thymeleaf-3.4.5.jar" → ("thymeleaf", "3.4.5")
# "netty-resolver-dns-4.1.128.Final.jar" → ("netty-resolver-dns", "4.1.128.Final")
_JAR_NAME_RE = re.compile(
    r'(?:.*/)?([a-zA-Z0-9._-]+?)-(\d[\d.]*(?:\.(?:Final|RELEASE|GA|RC\d+|Beta\d+|Alpha\d+))?)\.jar$',
    re.IGNORECASE,
)

_LIB_PREFIXES = ["BOOT-INF/lib/", "WEB-INF/lib/", "lib/"]

_QUALIFIER_RE = re.compile(r'\.(Final|RELEASE|GA|SP\d+)$', re.IGNORECASE)


class ArtifactInspector:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._jar_index: Optional[dict[str, ArtifactVersion]] = None

    def find_artifact(self) -> Optional[Path]:
        """Busca el fat JAR más reciente en rutas estándar de Maven/Gradle."""
        candidates = []
        for search_dir in _ARTIFACT_SEARCH_PATHS:
            d = self.project_path / search_dir
            if not d.exists():
                continue
            for p in list(d.glob("*.jar")) + list(d.glob("*.war")):
                if p.name.endswith("-plain.jar"):
                    continue  # Spring Boot plain JAR — sin deps internas
                candidates.append(p)
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.stat().st_mtime)

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
        artifact_path = self.find_artifact()
        if artifact_path is None:
            return VersionVerification(
                package_name=artifact_name,
                reported_version=reported_version,
                real_version=None,
                verdict=VersionVerdict.UNVERIFIABLE,
                analysis_note=(
                    f"No se encontró artefacto compilado en {self.project_path}. "
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
```

## Verificar

```bash
python -c "
from zeronoise.analyzers.artifact_inspector import ArtifactInspector
i = ArtifactInspector('C:\\\\Users\\\\admin\\\\Desktop\\\\ZeroNoise\\\\vuln_projects\\\\clientes-develop\\\\microservicio-clientes')
print('Artefacto:', i.find_artifact())
r = i.verify_version('thymeleaf', '3.4.6')
print(r.summary)
"
```

## Lo que NO tocar

`models/vulnerability.py`, `tools/reachability.py` — sin cambios.
