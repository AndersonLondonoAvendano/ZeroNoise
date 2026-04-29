# Tarea 13 — Fix: Detección Gradle, ruta del artefacto y contexto del proyecto

**Archivos a modificar:**
- `zeronoise/analyzers/dependency_tree_parser.py`
- `zeronoise/analyzers/artifact_inspector.py`

**Archivos a crear:**
- `zeronoise/analyzers/project_context_reader.py`

**Modificar (mínimamente):**
- `zeronoise/tools/depcheck_gate.py` — pasar contexto del proyecto a Stage 3

**Tiempo estimado:** 30 minutos
**Dependencias:** Tareas 02, 03, 04, 05 implementadas

---

## Diagnóstico — por qué falló Stage 0 en microservicio-clientes

Inspeccioné el proyecto directamente. Tres problemas encontrados:

### Problema 1 — `_run_gradle()` usa el wrapper incorrecto en Windows

```python
# Código actual en dependency_tree_parser.py:
wrapper = self.project_path / ("gradlew.bat" if sys.platform == "win32" else "gradlew")
cmd = str(wrapper) if wrapper.exists() else "gradle"

# El comando generado en Windows:
["gradlew.bat", "dependencies", "--configuration", "runtimeClasspath", "-q"]

# El problema: gradlew.bat necesita ser invocado como:
["cmd", "/c", "gradlew.bat", "dependencies", ...]
# O directamente con shell=True
# Sin esto, subprocess no puede ejecutar .bat directamente
```

El `DependencyTreeParser` intentó generar el árbol automáticamente pero falló
silenciosamente porque `.bat` no se ejecuta como binario en Windows. Retornó `{}`
→ `UNVERIFIABLE`.

### Problema 2 — `ArtifactInspector` no encuentra el JAR de Gradle

```python
# Código actual en artifact_inspector.py:
_ARTIFACT_SEARCH_PATHS = ["target", "build/libs", "build/outputs", "out/artifacts"]

# El proyecto usa Spring Boot con Gradle.
# El fat JAR de Spring Boot con Gradle está en:
#   build/libs/microservicio-clientes-*.jar   ← esto SÍ está en la lista

# Pero el JAR plain también existe:
#   build/libs/microservicio-clientes-*-plain.jar  ← filtrado correctamente

# El problema real: el glob busca "*.jar" pero el nombre tiene version dinámica.
# Si build/libs/ no existe (proyecto no compilado aún), retorna UNVERIFIABLE.
# Necesitamos también buscar en subdirectorios de build/libs/
```

Verificar si `build/libs/` existe y tiene JARs. Si el proyecto no está compilado,
agregar un mensaje claro en lugar de UNVERIFIABLE silencioso.

### Problema 3 — El `build.gradle` tiene información crítica que no se lee

Inspeccioné el `build.gradle` del proyecto. Contiene datos que cambiarían
completamente el análisis si ZeroNoise los leyera:

```groovy
// Línea 83 — EXCLUSIÓN EXPLÍCITA (esto es metadata de seguridad relevante)
configurations {
    all {
        exclude group: 'io.projectreactor.netty', module: 'reactor-netty-incubator-quic'
    }
}

// Línea 102 — DECLARACIÓN DIRECTA con exclusión
implementation('io.projectreactor.netty:reactor-netty-http') {
    exclude group: 'io.projectreactor.netty.incubator', module: 'reactor-netty-incubator-quic'
}

// Línea 79 — BOM declarado (esto determina versiones transitivas)
implementation platform("org.springframework.boot:spring-boot-dependencies:3.5.13")

// Línea 31 — Spring Boot version (determina qué versión de Netty se resuelve)
id 'org.springframework.boot' version '3.5.13'
```

Con Spring Boot 3.5.13 + BOM `spring-boot-dependencies:3.5.13`, Netty se resuelve
a `4.1.132.Final` (versión con el fix). Esto es exactamente lo que el equipo de
seguridad detectó manualmente. ZeroNoise debería detectarlo automáticamente.

### Problema 4 — No hay README.md pero sí hay contexto en otros archivos

```
README.md → NO EXISTE en este proyecto
build.gradle → SÍ existe con contexto de arquitectura (WebFlux, R2DBC, Spring Boot 3.5.13)
```

ZeroNoise no lee ninguno de estos archivos antes de emitir el veredicto, por lo que
el LLM en Stage 3 no sabe que el proyecto usa WebFlux reactivo, que el BOM fuerza
versiones específicas, ni que hay exclusiones explícitas de módulos.

---

## Fix 1 — Corregir `_run_gradle()` en Windows

En `dependency_tree_parser.py`, reemplazar el método `_run_gradle()` completo:

```python
def _run_gradle(self) -> dict[str, str]:
    """Genera el árbol con Gradle. Maneja Windows (.bat) correctamente."""
    import sys

    # Determinar el comando según el SO y si existe el wrapper
    wrapper_bat = self.project_path / "gradlew.bat"
    wrapper_sh = self.project_path / "gradlew"

    if sys.platform == "win32":
        if wrapper_bat.exists():
            # En Windows, .bat debe ejecutarse via cmd /c
            cmd_args = ["cmd", "/c", str(wrapper_bat)]
        else:
            cmd_args = ["gradle"]
    else:
        if wrapper_sh.exists():
            cmd_args = [str(wrapper_sh)]
        else:
            cmd_args = ["gradle"]

    full_cmd = cmd_args + [
        "dependencies",
        "--configuration", "runtimeClasspath",
        "-q",
        "--no-daemon",   # evitar que levante un daemon innecesario
    ]

    try:
        result = subprocess.run(
            full_cmd,
            cwd=str(self.project_path),
            capture_output=True,
            text=True,
            timeout=180,   # Gradle puede tardar más que Maven en el primer run
        )
        if result.returncode == 0 and result.stdout.strip():
            tmp = self.project_path / ".zn_tree_tmp.txt"
            tmp.write_text(result.stdout, encoding="utf-8")
            parsed = self._parse_file(tmp)
            tmp.unlink(missing_ok=True)
            return parsed
        else:
            # Loggear el error sin crashear
            import logging
            logging.getLogger("zeronoise.deptree").warning(
                f"Gradle salió con código {result.returncode}: "
                f"{result.stderr[:200] if result.stderr else 'sin stderr'}"
            )
    except subprocess.TimeoutExpired:
        import logging
        logging.getLogger("zeronoise.deptree").warning("Gradle dependency tree tardó más de 180s")
    except FileNotFoundError:
        import logging
        logging.getLogger("zeronoise.deptree").warning(
            f"Gradle no encontrado. Instalar Gradle o ejecutar: "
            f"gradlew dependencies --configuration runtimeClasspath > dep-tree.txt"
        )
    except Exception as e:
        import logging
        logging.getLogger("zeronoise.deptree").warning(f"Error ejecutando Gradle: {e}")

    return {}
```

---

## Fix 2 — Mejorar diagnóstico en `ArtifactInspector`

En `artifact_inspector.py`, reemplazar `find_artifact()`:

```python
def find_artifact(self) -> Optional[Path]:
    """
    Busca el fat JAR más reciente. Busca también en subdirectorios de build/libs/.
    Imprime un mensaje claro si no encuentra nada.
    """
    import logging
    logger = logging.getLogger("zeronoise.artifact")

    candidates = []
    for search_dir in _ARTIFACT_SEARCH_PATHS:
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

    if not candidates:
        logger.info(
            f"No se encontró artefacto compilado en {self.project_path}. "
            f"Rutas buscadas: {_ARTIFACT_SEARCH_PATHS}. "
            f"Para Gradle: ejecutar './gradlew build -x test' primero."
        )
        return None

    best = max(candidates, key=lambda p: p.stat().st_mtime)
    logger.info(f"Artefacto encontrado: {best}")
    return best
```

---

## Fix 3 — Crear `analyzers/project_context_reader.py`

Este nuevo módulo lee archivos de documentación y configuración del proyecto
para construir un **contexto enriquecido** que se pasa al LLM en Stage 3.

```python
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
                # Truncar al límite por archivo
                truncated = content[:_MAX_CHARS_PER_FILE]
                ctx.files_found.append(relative_path)

                # Asignar al campo correcto según el tipo de archivo
                name = file_path.name.lower()
                if name in ("readme.md", "readme.rst", "architecture.md"):
                    ctx.readme_summary = truncated
                elif name in ("build.gradle", "build.gradle.kts", "pom.xml"):
                    ctx.build_config = truncated
                    # Extraer datos estructurados del build file
                    self._parse_build_file(content, ctx)
                elif "application" in name:
                    ctx.app_config = truncated
                elif name in ("docker-compose.yml", "docker-compose.yaml", "dockerfile"):
                    ctx.infrastructure = truncated

                total_chars += len(truncated)
                if total_chars >= _MAX_TOTAL_CHARS:
                    break  # No leer más archivos si ya tenemos suficiente contexto

            except Exception:
                pass  # Archivo no legible — continuar

        return ctx

    def _parse_build_file(self, content: str, ctx: ProjectContext) -> None:
        """Extrae datos estructurados del build.gradle o pom.xml."""

        # Spring Boot version (Gradle)
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

        # Exclusiones explícitas
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
```

---

## Fix 4 — Integrar `ProjectContextReader` en `depcheck_gate.py`

En `tools/depcheck_gate.py`, en la función `analyze_depcheck_report`,
**antes del bucle** que analiza cada finding, agregar:

```python
# Leer contexto del proyecto UNA SOLA VEZ para todos los findings
from zeronoise.analyzers.project_context_reader import ProjectContextReader

_project_context = ProjectContextReader(project_path).read()
_context_summary = _project_context.to_llm_context()

# Loggear qué archivos se encontraron
import logging
_log = logging.getLogger("zeronoise.gate")
_log.info(
    f"Contexto del proyecto: archivos leídos={_project_context.files_found}, "
    f"Spring Boot={_project_context.spring_boot_version}, "
    f"Java={_project_context.java_version}, "
    f"BOMs={_project_context.declared_boms}, "
    f"Exclusiones={_project_context.excluded_modules}"
)
```

Luego en `_analyze_finding()`, en la llamada a `prepare_stage3_context`,
pasar el contexto:

```python
context = await prepare_stage3_context(
    package_name=finding.effective_purl,
    vulnerability_id=finding.cve_id,
    vulnerable_functions=[],
    project_path=project_path,
)

# Enriquecer el context bundle con el contexto del proyecto
if isinstance(context, dict):
    context["project_context"] = _context_summary
    # Datos estructurados clave para el LLM
    if _project_context.spring_boot_version:
        context["spring_boot_version"] = _project_context.spring_boot_version
    if _project_context.declared_boms:
        context["declared_boms"] = _project_context.declared_boms
    if _project_context.excluded_modules:
        context["excluded_modules"] = _project_context.excluded_modules
```

**Nota:** `_context_summary` se genera una vez y se reutiliza para todos los findings
del mismo análisis. No releer los archivos por cada CVE.

---

## Cómo probar

```bash
# 1. Verificar que el reader encuentra los archivos del proyecto
python -c "
from zeronoise.analyzers.project_context_reader import ProjectContextReader
r = ProjectContextReader(
    r'C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes'
)
ctx = r.read()
print('Archivos encontrados:', ctx.files_found)
print('Spring Boot:', ctx.spring_boot_version)
print('Java:', ctx.java_version)
print('BOMs:', ctx.declared_boms)
print('Exclusiones:', ctx.excluded_modules)
print()
print('--- Contexto para LLM ---')
print(ctx.to_llm_context())
"

# 2. Verificar que el dep-tree parser funciona con Gradle en Windows
python -c "
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
p = DependencyTreeParser(
    r'C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes'
)
print('Build tool:', p.detect_build_tool())
tree = p.load_tree()
print('Entries en el árbol:', len(tree))
# Buscar reactor-netty y netty
for k, v in tree.items():
    if 'netty' in k or 'reactor' in k:
        print(f'  {k}: {v}')
"

# 3. Flujo completo con el fix aplicado
# (usar el mismo prompt que ya probaste — el resultado debería cambiar)
```

## Output esperado después del fix

Con `build.gradle` leído correctamente, el contexto del LLM incluirá:

```
Spring Boot version: 3.5.13
Build tool: gradle
BOMs declarados: org.springframework.boot:spring-boot-dependencies:3.5.13
Módulos excluidos explícitamente: io.projectreactor.netty:reactor-netty-incubator-quic

--- Build config (extracto) ---
[primeros 2000 chars del build.gradle incluyendo las exclusiones]
```

Y con el árbol Gradle generado correctamente, `DependencyTreeParser` detectará:

```
reactor-netty-core: 1.2.16
netty-codec-http2:  4.1.131.Final → 4.1.132.Final  ← resolución al fix
```

Lo que llevará al veredicto:

```
FALSE_POSITIVE — La versión vulnerable de Netty (4.1.131.Final) fue resuelta
transitivamente a 4.1.132.Final (que contiene el fix de CVE-2026-33871 y
CVE-2026-33870) por el BOM spring-boot-dependencies:3.5.13. La versión
vulnerable no está presente en el artefacto final.
```

Que es exactamente el mismo veredicto que el equipo de seguridad emitió manualmente.

---

## Lo que NO tocar

- `tools/reachability.py`, `tools/stage3_context.py`, `tools/decision.py` — sin cambios
- `server.py` — `ProjectContextReader` es interno, no es una tool MCP
- `SecurityPolicy.max_snippet_lines = 50` — no cambiar
- `dry_run=True` por defecto — no cambiar
