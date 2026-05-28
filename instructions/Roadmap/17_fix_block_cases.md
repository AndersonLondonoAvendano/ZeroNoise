# Tarea 17 — Manejo de casos BLOCK reales: lógica genérica para cualquier librería

**Archivos a modificar:**
- `zeronoise/analyzers/artifact_inspector.py` — fuente de verdad absoluta
- `zeronoise/analyzers/dependency_tree_parser.py` — lookup más robusto
- `zeronoise/tools/depcheck_gate.py` — Stage 0 usa artefacto como fallback

**Tiempo estimado:** 30 minutos
**Dependencias:** Tareas 13, 14, 16 implementadas

---

## El problema de fondo

La lógica actual tiene una jerarquía implícita que falla cuando el árbol
no resuelve un artifact:

```
árbol Gradle → resuelve → cruzar con advisory → veredicto
árbol Gradle → NO resuelve → effective_version = None → Stage 0 no actúa
```

El `ArtifactInspector` siempre tiene la respuesta correcta porque lee el
JAR compilado directamente — no depende de nombres de paquetes ni de
mappings de starters. Pero hoy solo se usa como verificación secundaria.

**La corrección:** el `ArtifactInspector` debe ser la fuente de verdad
cuando el árbol falla, independientemente de qué librería sea.

```
árbol resuelve    → usar versión del árbol (más precisa, incluye resolución de conflictos)
árbol NO resuelve → usar versión del artefacto JAR (siempre disponible si el proyecto compila)
ninguno resuelve  → usar versión reportada por dep-check como último recurso
```

Este orden funciona para thymeleaf, log4j, netty, protobuf, quarkus,
micronaut, o cualquier librería que pueda aparecer en el futuro.

---

## Fix 1 — `ArtifactInspector` como fuente de verdad en Stage 0

En `_analyze_finding()` en `depcheck_gate.py`, reemplazar la asignación
de `_real_version` con esta lógica de tres niveles:

```python
# Resolver versión efectiva — tres niveles de fallback
_effective_version, _resolution_note = _tree_parser.resolve_effective_version(
    _artifact_name, _reported_version
)
_av = _artifact_inspector.verify_version(_artifact_name, _reported_version)

# Nivel 1: árbol de dependencias (más preciso — incluye resolución de conflictos)
if _effective_version:
    _real_version = _effective_version
    _version_source = "dependency_tree"

# Nivel 2: artefacto compilado (siempre correcto si el proyecto compiló)
elif _av and _av.real_version:
    _real_version = _av.real_version
    _version_source = "compiled_artifact"
    _resolution_note = (
        f"Versión encontrada en el artefacto compilado: "
        f"{_artifact_name}@{_real_version}. "
        f"El árbol de dependencias no resolvió este artifact."
    )

# Nivel 3: versión reportada por dep-check (último recurso)
else:
    _real_version = _reported_version
    _version_source = "depcheck_reported"
    _resolution_note = (
        f"Usando versión reportada por dep-check: {_artifact_name}@{_real_version}. "
        f"No fue posible confirmar en árbol ni en artefacto."
    )

base["version_verification"] = {
    "reported_version": _reported_version,
    "effective_version": _real_version,
    "version_source": _version_source,
    "resolution_note": _resolution_note,
    "artifact_check": _av.summary if _av else "No verificado",
}
```

Con este cambio, **cualquier librería** que esté en el JAR compilado
será detectada automáticamente sin necesidad de mappings específicos.

---

## Fix 2 — Cruzar siempre con el advisory, sin importar la fuente

El cruce con el advisory debe ejecutarse para cualquier versión resuelta,
independientemente de si vino del árbol, del artefacto, o de dep-check.
Reemplazar el bloque condicional actual:

```python
# ANTES — solo cruza cuando versión difiere de la reportada:
if _real_version and _real_version != _reported_version:
    _advisory_verdict = _check_version_against_advisory(...)

# DESPUÉS — cruza siempre que haya una versión:
if _real_version:
    _advisory_verdict = _check_version_against_advisory(
        cve_id=finding.cve_id,
        effective_version=_real_version,
        artifact_name=_artifact_name,
        vulnerable_software=getattr(finding, 'vulnerable_software', []),
        description=finding.description,
        reported_version=_reported_version,
    )

    if _advisory_verdict == "NOT_VULNERABLE":
        # Versión fuera del rango → FALSE_POSITIVE
        base["verdict"] = "FALSE_POSITIVE"
        base["justification"] = (
            f"La versión efectiva en runtime "
            f"({_artifact_name}@{_real_version}, fuente: {_version_source}) "
            f"no está en el rango de versiones afectadas por {finding.cve_id}. "
            f"{_resolution_note}"
        )
        return base

    elif _advisory_verdict == "VULNERABLE":
        # Versión dentro del rango → marcar para continuar con análisis
        base["version_note"] = (
            f"ATENCIÓN: {_artifact_name}@{_real_version} "
            f"ESTÁ en el rango vulnerable de {finding.cve_id}. "
            f"Fuente de versión: {_version_source}. "
            f"Continuar con análisis de alcanzabilidad."
        )
        base["version_is_vulnerable"] = True

    # UNKNOWN → continuar con contexto disponible para Stage 3
```

---

## Fix 3 — Verificación de presencia en artefacto para cualquier librería

Cuando Stage 2 marca `NOT_REACHABLE` pero el artefacto Inspector
confirma que la librería está empaquetada en versión vulnerable,
escalar el veredicto. Esta lógica aplica a cualquier librería.

Agregar al final de `_analyze_finding()`, después del bloque de
Stage 2 que retorna `NOT_REACHABLE`:

```python
# Si Stage 2 dice NOT_REACHABLE pero la versión en el artefacto
# es vulnerable → escalar según el tipo de vulnerabilidad
if base.get("verdict") == "NOT_REACHABLE" and base.get("version_is_vulnerable"):

    cwe_high_risk = {
        # Vulnerabilidades donde la presencia en classpath es suficiente riesgo
        "CWE-502",  # Deserialization of Untrusted Data
        "CWE-77",   # Command Injection
        "CWE-78",   # OS Command Injection
        "CWE-94",   # Code Injection
        "CWE-611",  # XXE
        "CWE-918",  # SSRF
    }
    finding_cwes = set(getattr(finding, 'cwes', []))

    if finding_cwes & cwe_high_risk:
        # CWEs de alto riesgo — presencia en classpath = LIKELY_EXPLOITABLE
        base["verdict"] = "LIKELY_EXPLOITABLE"
        base["justification"] = (
            f"{_artifact_name}@{_real_version} está empaquetado en el "
            f"artefacto final en versión vulnerable para {finding.cve_id}. "
            f"Aunque no hay imports directos en el código fuente, "
            f"la vulnerabilidad ({', '.join(finding_cwes)}) puede ser "
            f"explotable mediante el classpath runtime. "
            f"Requiere revisión humana antes de continuar el pipeline."
        )
        base["requires_human_review"] = True
    else:
        # Otros CWEs — presencia en classpath = REACHABLE con advertencia
        base["verdict"] = "REACHABLE"
        base["justification"] = (
            f"{_artifact_name}@{_real_version} está empaquetado en el "
            f"artefacto final en versión vulnerable para {finding.cve_id}. "
            f"No hay imports directos pero la librería está en el classpath. "
            f"Evaluar si puede excluirse del build o actualizar la versión."
        )
        base["requires_human_review"] = True
```

---

## Fix 4 — `resolve_effective_version()` más robusto en el árbol

El lookup actual falla para librerías cuyo nombre en el árbol difiere
del nombre en dep-check. Mejorar `_find_related_modules()` para extraer
keywords de forma más agresiva:

```python
def _find_related_modules(self, base_name: str, tree: dict) -> dict:
    """
    Busca módulos relacionados. Estrategia genérica sin hardcoding.

    Extrae todas las palabras significativas del nombre del artifact
    y busca coincidencias en el árbol, independientemente del framework
    o ecosistema.
    """
    # Sufijos a remover para encontrar el "núcleo" del nombre
    # Lista exhaustiva — cubre Spring, Quarkus, Micronaut, Jakarta, etc.
    _REMOVE_SUFFIXES = [
        "-core", "-api", "-impl", "-all", "-full",
        "-starter", "-shaded", "-shadow", "-uber",
        "-spring", "-spring5", "-spring6", "-spring-boot",
        "-quarkus", "-micronaut", "-jakarta", "-javax",
        "-http", "-https", "-web", "-rest", "-grpc",
        "-client", "-server", "-common", "-base",
        "-extensions", "-extension",
    ]

    clean = base_name.lower()
    for suffix in _REMOVE_SUFFIXES:
        if clean.endswith(suffix):
            clean = clean[: -len(suffix)]

    # Extraer palabras de al menos 4 caracteres
    # Dividir por "-" y "_"
    import re
    parts = re.split(r'[-_]', clean)
    keywords = [p for p in parts if len(p) >= 4]

    if not keywords:
        return {}

    related = {}
    for keyword in keywords:
        for key, version in tree.items():
            # Match si el keyword aparece como palabra completa en el nombre
            # (evita "log" matcheando "log4j" y "dialog")
            if re.search(rf'(?:^|[-_]){re.escape(keyword)}(?:[-_]|$)', key):
                if key != base_name:
                    related[key] = version

    return related
```

---

## Fix 5 — Normalización de versiones más robusta en `_compare_version_to_ranges()`

Algunas librerías usan formatos de versión no estándar que la función
`normalize()` actual no maneja:

```python
def normalize(v: str) -> str:
    """
    Normaliza versiones de cualquier ecosistema Java para comparación semántica.

    Cubre: Spring (.RELEASE), Netty (.Final), JBoss (.Final), Hibernate (.Final),
    Apache (.GA), Quarkus (-CR1), y versiones plain X.Y.Z.
    """
    import re
    v = v.strip()

    # Remover qualifiers con punto: 3.1.3.RELEASE, 4.1.132.Final, 5.3.0.GA
    v = re.sub(
        r'\.(?:RELEASE|Final|GA|SP\d+|RC\d+|M\d+|CR\d+|Alpha\d*|Beta\d*)$',
        '', v, flags=re.IGNORECASE
    )

    # Remover qualifiers con guión: 3.1.3-RELEASE, 4.0.0-RC1, 1.0.0-beta.1
    v = re.sub(
        r'-(?:RELEASE|Final|GA|SP\d+|RC\d+|M\d+|CR\d+|Alpha\d*|Beta\d*|SNAPSHOT).*$',
        '', v, flags=re.IGNORECASE
    )

    # Remover ".Final" o ".RELEASE" que quedaron sin el punto inicial
    v = re.sub(r'(?:Final|RELEASE|GA)$', '', v, flags=re.IGNORECASE)

    return v.strip('.-')
```

---

## Verificar con diag4.py (genérico para cualquier proyecto)

```python
# diag4.py — verificar Stage 0 para cualquier proyecto
import sys
from zeronoise.clients.depcheck_ingester import DepCheckIngester
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
from zeronoise.analyzers.artifact_inspector import ArtifactInspector
from zeronoise.tools.depcheck_gate import _check_version_against_advisory

PROJECT_PATH = sys.argv[1] if len(sys.argv) > 1 else input("project_path: ")
REPORT_PATH  = sys.argv[2] if len(sys.argv) > 2 else input("report_path: ")

ingester  = DepCheckIngester(REPORT_PATH)
findings  = ingester.load()
parser    = DependencyTreeParser(PROJECT_PATH)
inspector = ArtifactInspector(PROJECT_PATH)

print(f"\nArtefacto: {inspector.find_artifact()}")
tree = parser.load_tree()
print(f"Árbol: {len(tree)} entries\n")

for f in findings:
    if f.cvss and f.cvss.score >= 7.0:
        artifact = f.primary_package.artifact_name if f.primary_package else 'N/A'
        reported = f.primary_package.artifact_version if f.primary_package else 'N/A'

        eff_tree, note_tree = parser.resolve_effective_version(artifact, reported)
        av = inspector.verify_version(artifact, reported)

        # Lógica de tres niveles (igual que en _analyze_finding)
        if eff_tree:
            real = eff_tree
            source = "tree"
        elif av.real_version:
            real = av.real_version
            source = "artifact"
        else:
            real = reported
            source = "depcheck"

        verdict = _check_version_against_advisory(
            cve_id=f.cve_id,
            effective_version=real,
            artifact_name=artifact,
            vulnerable_software=f.vulnerable_software,
            description=f.description,
            reported_version=reported,
        )

        status = {
            "NOT_VULNERABLE": "✅ FALSE_POSITIVE",
            "VULNERABLE":     "❌ BLOCK",
            "UNKNOWN":        "⚠️  UNKNOWN",
        }.get(verdict, verdict)

        print(f"{f.cve_id} — {artifact}@{reported}")
        print(f"  efectiva ({source}): {real}")
        print(f"  vuln_software: {f.vulnerable_software}")
        print(f"  advisory: {verdict} → {status}")
        print()
```

```bash
# Usar con cualquier proyecto
uv run python diag4.py \
    "C:\ruta\al\proyecto" \
    "C:\ruta\al\dependency-check-report.json"
```

---

## Lo que es genérico en esta implementación

| Componente | ¿Genérico? | Motivo |
|---|---|---|
| `ArtifactInspector.verify_version()` | ✅ Sí | Lee el ZIP del JAR — funciona para cualquier librería |
| `_compare_version_to_ranges()` | ✅ Sí | Compara versiones semánticas — funciona para cualquier CVE |
| `_check_version_against_advisory()` | ✅ Sí | Usa datos del advisory de dep-check — no hardcodea librerías |
| `_find_related_modules()` | ✅ Sí | Extrae keywords genéricos sin hardcoding de frameworks |
| CWE classpath escalation | ✅ Sí | Lista de CWEs de alto riesgo aplicable a cualquier librería |
| `normalize()` | ✅ Sí | Cubre formatos de versión de Spring, Netty, JBoss, Apache, etc. |
| `_STARTER_TO_LIBRARY` | ⚠️ Parcial | Tabla de mappings conocidos — útil como optimización pero NO requerida |

**La tabla `_STARTER_TO_LIBRARY` es ahora solo una optimización** — si el
artifact está en ella, el lookup es más rápido. Si no está, el
`ArtifactInspector` lo encuentra igualmente leyendo el JAR.

---

## Lo que NO tocar

- `tools/reachability.py`, `tools/stage3_context.py`, `tools/decision.py`
- `server.py`
- `dry_run=True` por defecto
- `SecurityPolicy.max_snippet_lines = 50`
