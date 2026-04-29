# Tarea 04 — B1+B2: Parser del árbol de dependencias

**Archivo a crear:** `zeronoise/analyzers/dependency_tree_parser.py`
**Tiempo estimado:** 20 minutos
**Dependencias:** Tarea 02 implementada (`models/artifact_finding.py` existe)

---

## Problema

`spring-boot-starter-thymeleaf@3.4.6` no garantiza `thymeleaf@3.4.6`. La versión
real de la librería subyacente se resuelve transitivamente en el build. ZeroNoise
no modela este patrón de starters.

## Crear `zeronoise/analyzers/dependency_tree_parser.py`

```python
"""
dependency_tree_parser.py — Parsea el árbol de dependencias de Maven o Gradle.

Resuelve Brecha 2: la versión declarada del starter != versión de la librería real.

Fuentes en orden de prioridad:
  1. dep-tree.txt en la raíz del proyecto (pre-generado)
  2. Generación automática con mvn o gradle (si están disponibles)
  3. UNVERIFIABLE si ninguna fuente está disponible

Para generar el árbol manualmente:
  Maven:  mvn dependency:tree -DoutputFile=dep-tree.txt -Dscope=runtime -q
  Gradle: ./gradlew dependencies --configuration runtimeClasspath -q > dep-tree.txt
"""
from __future__ import annotations

import asyncio
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from zeronoise.models.artifact_finding import VersionVerdict, VersionVerification

# Mapping starter → librería real subyacente
_STARTER_TO_LIBRARY: dict[str, str] = {
    "spring-boot-starter-thymeleaf":    "thymeleaf",
    "spring-boot-starter-web":          "spring-webmvc",
    "spring-boot-starter-data-jpa":     "hibernate-core",
    "spring-boot-starter-security":     "spring-security-core",
    "spring-boot-starter-amqp":         "spring-rabbit",
    "spring-boot-starter-data-redis":   "lettuce-core",
    "spring-boot-starter-data-mongodb": "mongodb-driver-sync",
    "spring-boot-starter-actuator":     "spring-boot-actuator",
    "spring-boot-starter-validation":   "hibernate-validator",
    "spring-boot-starter-webflux":      "reactor-netty",
    "spring-boot-starter-mail":         "jakarta.mail",
    "spring-boot-starter-aop":          "aspectjweaver",
    "spring-boot-starter-log4j2":       "log4j-core",
    "spring-boot-starter-logging":      "logback-classic",
    "spring-cloud-starter-openfeign":   "feign-core",
    "spring-cloud-starter-gateway":     "spring-cloud-gateway-core",
}

# Maven: "[INFO] |  +- io.netty:netty-resolver-dns:jar:4.1.128.Final:compile"
_MAVEN_RE = re.compile(
    r'[\|+\\\- ]*([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):(?:jar|war|pom|test-jar):([^:]+):'
)

# Gradle: "+--- io.netty:netty-resolver-dns:4.1.128.Final -> 4.1.132.Final (*)"
_GRADLE_RE = re.compile(
    r'[\|+\\\- ]*([a-zA-Z0-9._-]+):([a-zA-Z0-9._-]+):([^\s\(]+?)(?:\s*->\s*([^\s\(]+))?(?:\s*\(\*\))?$'
)


class DependencyTreeParser:

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._tree_index: Optional[dict[str, str]] = None

    def detect_build_tool(self) -> Optional[str]:
        if (self.project_path / "pom.xml").exists():
            return "maven"
        if any((self.project_path / f).exists()
               for f in ["build.gradle", "build.gradle.kts"]):
            return "gradle"
        return None

    def load_tree(self) -> dict[str, str]:
        """Carga el árbol. Cache en self._tree_index."""
        if self._tree_index is not None:
            return self._tree_index

        for candidate in ["dep-tree.txt", "dependency-tree.txt", "build/dep-tree.txt"]:
            f = self.project_path / candidate
            if f.exists():
                self._tree_index = self._parse_file(f)
                return self._tree_index

        tool = self.detect_build_tool()
        if tool == "maven":
            self._tree_index = self._run_maven()
        elif tool == "gradle":
            self._tree_index = self._run_gradle()
        else:
            self._tree_index = {}

        return self._tree_index

    def verify_version(self, artifact_name: str, reported_version: str) -> VersionVerification:
        """Verifica la versión efectivamente resuelta en el árbol."""
        tree = self.load_tree()

        if not tree:
            return VersionVerification(
                package_name=artifact_name,
                reported_version=reported_version,
                real_version=None,
                verdict=VersionVerdict.UNVERIFIABLE,
                analysis_note=(
                    f"Árbol de dependencias no disponible. "
                    f"Generar con: mvn dependency:tree -DoutputFile=dep-tree.txt"
                ),
            )

        is_starter = artifact_name in _STARTER_TO_LIBRARY
        actual_lib = _STARTER_TO_LIBRARY.get(artifact_name, artifact_name)
        resolved = self._lookup(actual_lib, tree)

        if resolved is None:
            return VersionVerification(
                package_name=artifact_name,
                reported_version=reported_version,
                real_version=None,
                verdict=VersionVerdict.NOT_FOUND,
                is_starter_wrapper=is_starter,
                actual_library_name=actual_lib if is_starter else None,
                analysis_note=f"'{actual_lib}' no encontrado en el árbol de dependencias runtime.",
            )

        if resolved == reported_version:
            verdict = VersionVerdict.CONFIRMED
            note = ""
        elif is_starter:
            verdict = VersionVerdict.TRANSITIVELY_RESOLVED
            note = (
                f"'{artifact_name}' es un starter wrapper. "
                f"Versión del starter: {reported_version}. "
                f"Versión efectiva de '{actual_lib}': {resolved}. "
                f"Evaluar el CVE contra {actual_lib}@{resolved}."
            )
        else:
            verdict = VersionVerdict.MISMATCH
            note = (
                f"MISMATCH en árbol: dep-check reportó {artifact_name}@{reported_version}, "
                f"versión resuelta es {resolved}. Usar {resolved} para evaluar el CVE."
            )

        return VersionVerification(
            package_name=artifact_name,
            reported_version=reported_version,
            real_version=resolved,
            verdict=verdict,
            found_in_tree=f"{actual_lib}:{resolved}",
            is_starter_wrapper=is_starter,
            actual_library_name=actual_lib if is_starter else None,
            analysis_note=note,
        )

    # ------------------------------------------------------------------
    def _parse_file(self, f: Path) -> dict[str, str]:
        index: dict[str, str] = {}
        content = f.read_text(encoding="utf-8", errors="ignore")
        is_maven = "[INFO]" in content
        for line in content.splitlines():
            if is_maven:
                m = _MAVEN_RE.search(line)
                if m:
                    index[m.group(2).lower()] = m.group(3)
            else:
                m = _GRADLE_RE.search(line.strip())
                if m:
                    version = (m.group(4) or m.group(3)).strip()
                    index[m.group(2).lower()] = version
        return index

    def _run_maven(self) -> dict[str, str]:
        try:
            r = subprocess.run(
                ["mvn", "dependency:tree", "-DoutputType=text",
                 "-Dscope=runtime", "--no-transfer-progress", "-q"],
                cwd=self.project_path, capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                tmp = self.project_path / ".zn_tree_tmp.txt"
                tmp.write_text(r.stdout)
                result = self._parse_file(tmp)
                tmp.unlink(missing_ok=True)
                return result
        except Exception:
            pass
        return {}

    def _run_gradle(self) -> dict[str, str]:
        wrapper = self.project_path / ("gradlew.bat" if sys.platform == "win32" else "gradlew")
        cmd = str(wrapper) if wrapper.exists() else "gradle"
        try:
            r = subprocess.run(
                [cmd, "dependencies", "--configuration", "runtimeClasspath", "-q"],
                cwd=self.project_path, capture_output=True, text=True, timeout=120,
            )
            if r.returncode == 0:
                tmp = self.project_path / ".zn_tree_tmp.txt"
                tmp.write_text(r.stdout)
                result = self._parse_file(tmp)
                tmp.unlink(missing_ok=True)
                return result
        except Exception:
            pass
        return {}

    def _lookup(self, name: str, tree: dict) -> Optional[str]:
        n = name.lower()
        if n in tree:
            return tree[n]
        for key, val in tree.items():
            if n in key or key in n:
                return val
        return None
```

## Verificar

```bash
python -c "
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
p = DependencyTreeParser('C:\\\\Users\\\\admin\\\\Desktop\\\\ZeroNoise\\\\vuln_projects\\\\clientes-develop\\\\microservicio-clientes')
print('Build tool:', p.detect_build_tool())
r = p.verify_version('spring-boot-starter-thymeleaf', '3.4.6')
print(r.summary)
print(r.analysis_note)
"
```

## Lo que NO tocar

`models/vulnerability.py`, ningún scanner existente.
