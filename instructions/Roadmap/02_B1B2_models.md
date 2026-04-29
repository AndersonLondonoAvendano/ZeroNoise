# Tarea 02 — B1+B2: Modelos de datos Stage 0

**Archivo a crear:** `zeronoise/models/artifact_finding.py`
**Tiempo estimado:** 15 minutos
**Dependencias:** Ninguna

---

## Problema

No existe modelo de datos para representar el resultado de verificar si la versión
reportada por dep-check coincide con la versión real empaquetada en el JAR o resuelta
en el árbol de dependencias.

## Crear `zeronoise/models/artifact_finding.py`

```python
"""
artifact_finding.py — Resultado de la verificación de versión real (Stage 0).

Representa la comparación entre lo que dep-check reportó y lo que realmente
está empaquetado en el JAR o resuelto en el árbol de dependencias del proyecto.

Paralelo a Finding (models/vulnerability.py) — no lo reemplaza.
Finding viene de DT con UUIDs. VersionVerification viene del análisis local del artefacto.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VersionVerdict(str, Enum):
    CONFIRMED              = "CONFIRMED"               # reportada == real
    MISMATCH               = "MISMATCH"                # reportada != real → revisar
    NOT_FOUND              = "NOT_FOUND"               # no está en el artefacto
    UNVERIFIABLE           = "UNVERIFIABLE"            # sin artefacto disponible
    TRANSITIVELY_RESOLVED  = "TRANSITIVELY_RESOLVED"   # versión viene de dep transitiva


@dataclass
class ArtifactVersion:
    """Versión de un paquete encontrada en el artefacto compilado."""
    artifact_name: str
    resolved_version: str
    source: str          # "pom_properties" | "jar_filename" | "dependency_tree"
    jar_path: str        # ruta dentro del fat JAR o en el classpath


@dataclass
class VersionVerification:
    """
    Resultado de verificar UN paquete contra el artefacto real y/o el dep tree.

    Se adjunta a DepCheckFinding antes de Stage 2 para que el análisis use
    la versión REAL en lugar de la versión reportada por el scanner.
    """
    package_name: str
    reported_version: str
    real_version: Optional[str]
    verdict: VersionVerdict

    found_in_artifact: Optional[ArtifactVersion] = None
    found_in_tree: Optional[str] = None          # línea del dep tree

    is_starter_wrapper: bool = False             # ej: spring-boot-starter-thymeleaf
    actual_library_name: Optional[str] = None    # ej: "thymeleaf"
    version_is_vulnerable: Optional[bool] = None

    analysis_note: str = ""                      # nota pre-generada para Stage 3

    @property
    def requires_reanalysis(self) -> bool:
        """True si la versión real difiere — el análisis debe usar real_version."""
        return self.verdict in (VersionVerdict.MISMATCH, VersionVerdict.NOT_FOUND)

    @property
    def summary(self) -> str:
        if self.verdict == VersionVerdict.CONFIRMED:
            return f" {self.package_name}@{self.real_version} confirmado en artefacto"
        if self.verdict == VersionVerdict.MISMATCH:
            return (f"  Mismatch: scanner reportó {self.reported_version}, "
                    f"artefacto tiene {self.real_version}")
        if self.verdict == VersionVerdict.NOT_FOUND:
            return f" {self.package_name} NO está en el artefacto — posible falso positivo"
        if self.verdict == VersionVerdict.TRANSITIVELY_RESOLVED:
            return (f"ℹ  {self.package_name}@{self.real_version} resuelto transitivamente "
                    f"(starter declarado: {self.reported_version})")
        return f" {self.package_name} — no verificable (sin artefacto)"
```

## Verificar

```bash
python -c "from zeronoise.models.artifact_finding import VersionVerification, VersionVerdict; print('OK')"
```

## Lo que NO tocar

`models/vulnerability.py` — este modelo es paralelo, no lo reemplaza.
