# Tarea 14 (revisada) — Conectar Stage 0 al veredicto final — enfoque general

**Archivos a modificar:**
- `zeronoise/analyzers/dependency_tree_parser.py` — agregar `resolve_effective_version()`
- `zeronoise/tools/depcheck_gate.py` — lógica Stage 0 general + `_check_version_against_advisory()`
- `zeronoise/models/depcheck_finding.py` — agregar campo `vulnerable_software`
- `zeronoise/clients/depcheck_ingester.py` — extraer `vulnerableSoftware` del JSON

**Dependencia nueva:** `uv add packaging`
**Tiempo estimado:** 25 minutos
**Dependencias:** Tarea 13 implementada

---

## Por qué la versión anterior de esta tarea era incorrecta

Tenía `_NETTY_FIX_VERSIONS` hardcodeado solo para Netty. Eso no escala —
ZeroNoise analiza cualquier librería en cualquier proyecto.

La versión que "tiene el fix" depende del CVE, no de la librería.
Esa información vive en el advisory del CVE. El diseño correcto es:

```
DependencyTreeParser  → ¿qué versión está realmente en runtime?
Advisory del CVE      → ¿qué versiones son vulnerables?
Stage 0               → cruza ambas → veredicto

versión_runtime NO en rango_vulnerable → FALSE_POSITIVE  (0 tokens)
versión_runtime SÍ en rango_vulnerable → continuar a Stage 2/3
sin datos del advisory                 → continuar a Stage 2/3 con contexto
```

---

## Fix 1 — `resolve_effective_version()` en `DependencyTreeParser`

Responde: **¿qué versión real está en runtime para este artifact?**
Sin opinar sobre si es vulnerable. Funciona para cualquier librería.

Agregar al final de la clase en `dependency_tree_parser.py`:

```python
def resolve_effective_version(
    self,
    artifact_name: str,
    reported_version: str,
) -> tuple[Optional[str], str]:
    """
    Resuelve la versión efectiva de un artifact en el árbol de dependencias.

    Estrategia:
      1. Búsqueda directa del artifact en el árbol
      2. Si no está o es un wrapper, buscar sub-módulos relacionados
         (ej: reactor-netty-core → todos los netty-* en el árbol)
      3. Retornar la versión más representativa

    Returns:
        (effective_version, resolution_note)
        effective_version: versión real en runtime, o None si no se encontró
        resolution_note:   explicación de cómo se resolvió
    """
    tree = self.load_tree()
    if not tree:
        return None, "Árbol de dependencias no disponible"

    name = artifact_name.lower()

    # 1. Búsqueda directa
    direct = self._lookup(name, tree)
    if direct and direct != reported_version:
        return direct, (
            f"Versión en árbol: {artifact_name}@{direct} "
            f"(dep-check reportó {reported_version})"
        )
    if direct:
        return direct, f"Versión confirmada en árbol: {artifact_name}@{direct}"

    # 2. Buscar sub-módulos relacionados (útil para wrappers y módulos padre)
    related = self._find_related_modules(name, tree)
    if related:
        versions = list(set(related.values()))
        if len(versions) == 1:
            return versions[0], (
                f"'{artifact_name}' resuelto via sub-módulos: "
                f"{dict(list(related.items())[:5])}. "
                f"Versión efectiva de los componentes: {versions[0]}"
            )
        else:
            highest = self._highest_version(versions)
            return highest, (
                f"'{artifact_name}' tiene sub-módulos con versiones mixtas: "
                f"{related}. Versión más alta encontrada: {highest}"
            )

    return None, (
        f"'{artifact_name}' no encontrado en el árbol de dependencias runtime."
    )

def _find_related_modules(
    self,
    base_name: str,
    tree: dict[str, str],
) -> dict[str, str]:
    """
    Busca módulos relacionados al artifact.
    Extrae keywords del nombre y busca coincidencias en el árbol.
    """
    # Limpiar sufijos comunes para extraer el dominio real
    clean = base_name
    for suffix in ["-core", "-http", "-starter", "-shaded", "-all"]:
        clean = clean.replace(suffix, "")

    parts = clean.split("-")
    # Keywords de al menos 4 caracteres para evitar matches espurios
    keywords = [p for p in parts if len(p) >= 4]

    related = {}
    for keyword in keywords:
        for key, version in tree.items():
            if keyword in key and key != base_name:
                related[key] = version

    return related

def _highest_version(self, versions: list[str]) -> str:
    """Retorna la versión más alta de una lista."""
    def parse(v: str) -> tuple:
        clean = re.sub(
            r'\.(Final|RELEASE|GA|SP\d+|Alpha\d*|Beta\d*|RC\d*)$',
            '', v, flags=re.IGNORECASE
        )
        try:
            return tuple(int(x) for x in clean.split('.') if x.isdigit())
        except ValueError:
            return (0,)
    return max(versions, key=parse)
```

---

## Fix 2 — Agregar `vulnerable_software` al modelo y al ingester

**En `models/depcheck_finding.py`**, agregar el campo al dataclass `DepCheckFinding`:

```python
# Agregar junto a los otros campos existentes:
vulnerable_software: list[str] = field(default_factory=list)
# Rangos de versiones afectadas extraídos del advisory
# Formato: ["< 4.1.132.Final", ">= 4.0.0"] o CPE strings
```

**En `clients/depcheck_ingester.py`**, en `_parse_finding()`, agregar antes del `return`:

```python
# Extraer rangos de versiones vulnerables del advisory
vuln_software_raw = vuln.get("vulnerableSoftware", [])
ranges = []
for vs in vuln_software_raw:
    if isinstance(vs, dict):
        sw = vs.get("software", {})
        vs_id = sw.get("id", "") if isinstance(sw, dict) else str(sw)
    else:
        vs_id = str(vs)
    if vs_id:
        ranges.append(vs_id)

finding = DepCheckFinding(
    cve_id=cve_id,
    severity=severity,
    cvss=cvss,
    description=description,
    cwes=cwes,
    affected_packages=[package],
    identification_issues=issues,
    requires_human_review=needs_review,
    vulnerable_software=ranges,   # ← nuevo campo
)
return finding
```

---

## Fix 3 — Lógica Stage 0 general en `depcheck_gate.py`

**Reemplazar** el bloque Stage 0 completo en `_analyze_finding()`:

```python
# ── Stage 0: Verificación de versión real ─────────────────────────────
from zeronoise.analyzers.artifact_inspector import ArtifactInspector
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
from zeronoise.models.artifact_finding import VersionVerdict

_tree_parser = DependencyTreeParser(project_path)
_artifact_inspector = ArtifactInspector(project_path)

_artifact_name = (
    finding.primary_package.artifact_name
    if finding.primary_package else ""
)
_reported_version = (
    finding.primary_package.artifact_version
    if finding.primary_package else ""
)

if _artifact_name and _reported_version:

    # Resolver versión efectiva en runtime
    _effective_version, _resolution_note = _tree_parser.resolve_effective_version(
        _artifact_name, _reported_version
    )
    _av = _artifact_inspector.verify_version(_artifact_name, _reported_version)
    _real_version = _effective_version or (_av.real_version if _av else None)

    base["version_verification"] = {
        "reported_version": _reported_version,
        "effective_version": _real_version,
        "resolution_note": _resolution_note,
        "artifact_check": _av.summary if _av else "No verificado",
    }

    # CASO 1: NOT_FOUND en árbol Y artefacto → falso positivo del scanner
    _av_nf = _av and _av.verdict == VersionVerdict.NOT_FOUND
    _tv_nf = _real_version is None and "no encontrado" in _resolution_note.lower()
    if _av_nf and _tv_nf:
        base["verdict"] = "FALSE_POSITIVE"
        base["justification"] = (
            f"'{_artifact_name}' no está en el artefacto ni en el árbol "
            f"de dependencias runtime. Falso positivo del scanner."
        )
        return base

    # CASO 2: Versión resuelta difiere de la reportada → cruzar con advisory
    if _real_version and _real_version != _reported_version:
        _advisory_verdict = _check_version_against_advisory(
            cve_id=finding.cve_id,
            effective_version=_real_version,
            artifact_name=_artifact_name,
            vulnerable_software=getattr(finding, 'vulnerable_software', []),
            description=finding.description,
        )

        if _advisory_verdict == "NOT_VULNERABLE":
            base["verdict"] = "FALSE_POSITIVE"
            base["justification"] = (
                f"La versión efectiva en runtime "
                f"({_artifact_name}@{_real_version}) no está en el rango "
                f"de versiones afectadas por {finding.cve_id}. "
                f"dep-check reportó el wrapper ({_reported_version}). "
                f"Resolución del árbol: {_resolution_note}"
            )
            return base

        elif _advisory_verdict == "VULNERABLE":
            base["version_note"] = (
                f"ATENCIÓN: La versión efectiva {_artifact_name}@{_real_version} "
                f"ESTÁ en el rango vulnerable de {finding.cve_id}. "
                f"Continuar con análisis de reachability."
            )
        else:
            # UNKNOWN — pasar contexto al LLM y dejar que Stage 3 decida
            base["version_note"] = (
                f"Versión efectiva en runtime: {_artifact_name}@{_real_version} "
                f"(dep-check reportó {_reported_version}). "
                f"{_resolution_note}"
            )

# ── Fin Stage 0 ────────────────────────────────────────────────────────
```

**Agregar como función standalone** en `depcheck_gate.py`
(fuera de `_analyze_finding`, al mismo nivel):

```python
def _check_version_against_advisory(
    cve_id: str,
    effective_version: str,
    artifact_name: str,
    vulnerable_software: list[str],
    description: str,
) -> str:
    """
    Determina si la versión efectiva está en el rango vulnerable del CVE.

    Returns:
        "NOT_VULNERABLE" — versión fuera del rango afectado
        "VULNERABLE"     — versión dentro del rango afectado
        "UNKNOWN"        — sin datos suficientes (pasar a Stage 3)
    """
    # Fuente 1: vulnerable_software del reporte de dep-check
    if vulnerable_software:
        result = _compare_version_to_ranges(effective_version, vulnerable_software)
        if result != "UNKNOWN":
            return result

    # Fuente 2: extraer rango de la descripción del CVE
    return _extract_range_from_description(effective_version, description)


def _compare_version_to_ranges(version: str, ranges: list[str]) -> str:
    """Compara una versión contra rangos usando la librería packaging."""
    try:
        from packaging.version import Version

        def normalize(v: str) -> str:
            import re
            # Remover qualifiers Java: .Final, .RELEASE, .GA
            return re.sub(
                r'\.(Final|RELEASE|GA|SP\d+)$', '', v, flags=re.IGNORECASE
            )

        effective = Version(normalize(version))
        for range_str in ranges:
            r = range_str.strip()
            if r.startswith("< "):
                upper = Version(normalize(r[2:].strip()))
                return "VULNERABLE" if effective < upper else "NOT_VULNERABLE"
            elif r.startswith("<= "):
                upper = Version(normalize(r[3:].strip()))
                return "VULNERABLE" if effective <= upper else "NOT_VULNERABLE"
            elif r.startswith(">= ") and ", < " in r:
                parts = r.split(", < ")
                lower = Version(normalize(parts[0][3:].strip()))
                upper = Version(normalize(parts[1].strip()))
                return "VULNERABLE" if lower <= effective < upper else "NOT_VULNERABLE"
    except Exception:
        pass
    return "UNKNOWN"


def _extract_range_from_description(version: str, description: str) -> str:
    """Extrae el rango de versiones de la descripción del CVE con regex."""
    import re

    patterns = [
        r'(?:before|prior to|earlier than)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'fixed (?:in|with)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'versions?\s+(?:before|prior to)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
    ]
    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            fix_version = match.group(1)
            return _compare_version_to_ranges(version, [f"< {fix_version}"])

    return "UNKNOWN"
```

---

## Fix 4 — Instalar dependencia

```bash
uv add packaging
```

Si `packaging` no está instalado, `_compare_version_to_ranges` retorna `UNKNOWN`
y el flujo continúa a Stage 3. No rompe nada.

---

## Cómo probar

Crear `diag2.py`:

```python
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser

path = r'C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes'
p = DependencyTreeParser(path)

# Probar con varios artifacts — algunos en el proyecto, otros no
for artifact, version in [
    ("reactor-netty-core", "1.2.16"),
    ("netty-resolver-dns", "4.1.128.Final"),
    ("protobuf-java", "3.25.8"),
    ("spring-rabbit", "3.2.8"),
    ("thymeleaf", "3.4.6"),
]:
    eff_ver, note = p.resolve_effective_version(artifact, version)
    print(f"\n{artifact}@{version}")
    print(f"  Efectiva: {eff_ver}")
    print(f"  Nota: {note[:100]}")
```

```bash
uv run python diag2.py
uv run python scripts/poc_artifact_verify.py \
    --project-path "C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes" \
    --report "C:\Users\admin\Desktop\ZeroNoise\dependency-check-report.json"
```

**Output esperado:**
```
reactor-netty-core@1.2.16
  Efectiva: 4.1.132.Final
  Nota: 'reactor-netty-core' resuelto via sub-módulos: {'netty-codec-http2': '4.1.132.Final'...}

netty-resolver-dns@4.1.128.Final
  Efectiva: 4.1.132.Final
  Nota: Versión en árbol: netty-resolver-dns@4.1.132.Final (dep-check reportó 4.1.128.Final)

protobuf-java@3.25.8
  Efectiva: None
  Nota: 'protobuf-java' no encontrado en el árbol de dependencias runtime.
```

Con el flujo completo, el VEX debería mostrar:
```
CVE-2026-33871 → FALSE_POSITIVE — versión efectiva 4.1.132.Final fuera del rango vulnerable
CVE-2026-33870 → FALSE_POSITIVE — idem
Requiere revisión humana: No
```

---

## Lo que NO tocar

- `tools/reachability.py`, `tools/stage3_context.py`, `tools/decision.py`
- `server.py`
- `dry_run=True` por defecto
- `SecurityPolicy.max_snippet_lines = 50`
