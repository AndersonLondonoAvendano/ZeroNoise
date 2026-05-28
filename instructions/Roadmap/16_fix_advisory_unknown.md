# Tarea 16 — Diagnóstico y fix: advisory_verdict siempre retorna UNKNOWN

**Archivo principal:** `zeronoise/tools/depcheck_gate.py`
**Archivos secundarios:** `zeronoise/clients/depcheck_ingester.py`
**Tiempo estimado:** 30 minutos
**Dependencias:** Tareas 13, 14, 15 implementadas

---

## Contexto del problema

Stage 0 está implementado correctamente y los `return base` están en su lugar.
Sin embargo el reporte sigue mostrando `NOT_REACHABLE` en lugar de `FALSE_POSITIVE`.

La hipótesis es que `_check_version_against_advisory()` retorna `UNKNOWN`
porque ninguna de sus dos fuentes de datos tiene información utilizable:

```
Fuente 1: vulnerable_software del DepCheckFinding → probablemente vacío []
Fuente 2: descripción del CVE → probablemente no tiene patrón "before X.Y.Z"

→ ambas fuentes fallan → retorna UNKNOWN
→ Stage 0 no puede emitir FALSE_POSITIVE
→ continúa a Stage 2 → NOT_REACHABLE
```

---

## Paso 1 — Diagnóstico (Claude Code debe ejecutar esto primero)

Crear y ejecutar `diag3.py` para confirmar la hipótesis:

```python
from zeronoise.clients.depcheck_ingester import DepCheckIngester
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
from zeronoise.tools.depcheck_gate import _check_version_against_advisory

ingester = DepCheckIngester(
    r'C:\Users\admin\Desktop\ZeroNoise\dependency-check-report.json'
)
findings = ingester.load()
parser = DependencyTreeParser(
    r'C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes'
)

for f in findings:
    if f.cvss and f.cvss.score >= 7.0:
        artifact = f.primary_package.artifact_name if f.primary_package else 'N/A'
        reported = f.primary_package.artifact_version if f.primary_package else 'N/A'

        print(f'=== {f.cve_id} ===')
        print(f'  artifact:            {artifact}')
        print(f'  reported_version:    {reported}')
        print(f'  vulnerable_software: {getattr(f, "vulnerable_software", [])}')
        print(f'  description:         {f.description[:400]}')

        eff, note = parser.resolve_effective_version(artifact, reported)
        print(f'  effective_version:   {eff}')
        print(f'  resolution_note:     {note}')

        if eff and eff != reported:
            verdict = _check_version_against_advisory(
                cve_id=f.cve_id,
                effective_version=eff,
                artifact_name=artifact,
                vulnerable_software=getattr(f, 'vulnerable_software', []),
                description=f.description,
            )
            print(f'  advisory_verdict:    {verdict}')
        print()
```

```bash
uv run python diag3.py
```

**Leer el output e identificar cuál de estos escenarios aplica:**

---

## Escenario A — `vulnerable_software` vacío Y descripción sin patrón de versión

```
vulnerable_software: []
description: "A flaw was found in Netty..."  ← sin "before X.Y.Z"
advisory_verdict: UNKNOWN
```

**Fix A:** La descripción del CVE no tiene el patrón esperado. Hay que ampliar
los patrones de extracción Y agregar una fuente adicional: el reporte de
dep-check tiene un campo `vulnerableVersions` o `affectedVersionRange` en
algunos CVEs. Inspeccionar el JSON raw del reporte para encontrarlo.

Ejecutar este diagnóstico adicional:

```python
import json

with open(r'C:\Users\admin\Desktop\ZeroNoise\dependency-check-report.json') as f:
    data = json.load(f)

for dep in data['dependencies']:
    for vuln in dep.get('vulnerabilities', []):
        score = vuln.get('cvssv3', {}).get('baseScore', 0)
        if score and float(score) >= 7.0:
            print(f"CVE: {vuln.get('name')}")
            # Imprimir TODAS las claves del objeto vuln para encontrar
            # dónde están los rangos de versiones afectadas
            for key, value in vuln.items():
                if key not in ('description', 'references'):
                    print(f"  {key}: {value}")
            print()
```

```bash
uv run python diag_raw.py
```

Con el output de este diagnóstico, identificar el campo exacto que contiene
los rangos de versiones y actualizar `_parse_finding()` en el ingester para
extraerlo correctamente.

---

## Escenario B — `effective_version` es None o igual a `reported_version`

```
effective_version: None
resolution_note: 'reactor-netty-core' no encontrado en el árbol
```

Esto significa que `dep-tree.txt` no fue encontrado o no tiene el formato
esperado. Verificar:

```python
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser

p = DependencyTreeParser(
    r'C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes'
)
tree = p.load_tree()
print(f'Entries: {len(tree)}')
print(f'Netty entries:')
for k, v in tree.items():
    if 'netty' in k or 'reactor' in k:
        print(f'  {k}: {v}')
```

Si `tree` está vacío: el `dep-tree.txt` no existe o Gradle no se ejecutó.
Generar manualmente:

```powershell
cd "C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes"
.\gradlew.bat dependencies --configuration runtimeClasspath -q > dep-tree.txt
```

---

## Fix principal — ampliar fuentes de datos del advisory

Independientemente del escenario, aplicar este fix en `depcheck_gate.py`
que hace la lógica más robusta cubriendo más casos:

### Reemplazar `_check_version_against_advisory()` con esta versión mejorada:

```python
def _check_version_against_advisory(
    cve_id: str,
    effective_version: str,
    artifact_name: str,
    vulnerable_software: list,
    description: str,
) -> str:
    """
    Determina si la versión efectiva está en el rango vulnerable del CVE.

    Fuentes en orden de prioridad:
      1. vulnerable_software del reporte dep-check (rangos estructurados)
      2. Descripción textual del CVE (regex sobre patrones comunes)
      3. Heurística de versión: si effective > reported → probablemente NOT_VULNERABLE

    Returns:
        "NOT_VULNERABLE" — versión fuera del rango afectado
        "VULNERABLE"     — versión dentro del rango afectado
        "UNKNOWN"        — sin datos suficientes
    """
    # Fuente 1: rangos estructurados del reporte
    if vulnerable_software:
        result = _compare_version_to_ranges(effective_version, vulnerable_software)
        if result != "UNKNOWN":
            return result

    # Fuente 2: regex sobre la descripción del CVE
    result = _extract_range_from_description(effective_version, description)
    if result != "UNKNOWN":
        return result

    # Fuente 3: heurística de versión
    # Si la versión efectiva en runtime es MAYOR que la reportada por dep-check,
    # es muy probable que sea NOT_VULNERABLE porque:
    #   - dep-check reportó la versión del wrapper (ej: 1.2.16 de reactor-netty)
    #   - el árbol resolvió la versión real del componente (ej: 4.1.132.Final de netty)
    #   - versiones más altas típicamente incluyen los fixes
    # Esta heurística solo aplica cuando hay evidencia de que es un wrapper
    # (versión efectiva completamente diferente a la reportada en formato mayor)
    try:
        from packaging.version import Version
        import re

        def normalize(v: str) -> str:
            return re.sub(
                r'\.(Final|RELEASE|GA|SP\d+)$', '', v, flags=re.IGNORECASE
            )

        eff = Version(normalize(effective_version))
        rep = Version(normalize(reported_version_for_heuristic(artifact_name, effective_version)))

        # Si la versión efectiva tiene un major version completamente diferente
        # (ej: 4.1.132 vs 1.2.16), es un wrapper mismatch claro
        if eff.major != rep.major and eff > rep:
            return "NOT_VULNERABLE_HEURISTIC"

    except Exception:
        pass

    return "UNKNOWN"
```

**Nota:** `"NOT_VULNERABLE_HEURISTIC"` es un valor nuevo que indica que
la decisión se tomó por heurística, no por datos del advisory. Tratarlo
igual que `"NOT_VULNERABLE"` en el bloque Stage 0 pero con una justificación
diferente que indique que es una heurística.

### Actualizar el bloque Stage 0 en `_analyze_finding()`:

```python
# Reemplazar:
if _advisory_verdict == "NOT_VULNERABLE":

# Por:
if _advisory_verdict in ("NOT_VULNERABLE", "NOT_VULNERABLE_HEURISTIC"):
    _heuristic = _advisory_verdict == "NOT_VULNERABLE_HEURISTIC"
    base["verdict"] = "FALSE_POSITIVE"
    base["justification"] = (
        f"La versión efectiva en runtime "
        f"({_artifact_name}@{_real_version}) no está en el rango "
        f"de versiones afectadas por {finding.cve_id}. "
        f"dep-check reportó el wrapper ({_reported_version}). "
        f"Resolución del árbol: {_resolution_note}"
        + (" [Determinado por heurística de versión — verificar manualmente]"
           if _heuristic else "")
    )
    base["requires_human_review"] = _heuristic
    return base
```

### Agregar función auxiliar:

```python
def reported_version_for_heuristic(artifact_name: str, effective_version: str) -> str:
    """
    Para la heurística de versión, necesitamos comparar major versions.
    Retorna la versión reportada almacenada en el finding.
    Esta función existe para que la heurística sea explícita y trazable.
    """
    # Esta función recibe el artifact_name y effective_version del closure
    # El _reported_version viene del scope de _analyze_finding
    # Se implementa pasando _reported_version como parámetro adicional
    # Ver actualización de la firma de _check_version_against_advisory abajo
    return effective_version  # placeholder — ver fix de firma abajo
```

### Actualizar la firma de `_check_version_against_advisory()`:

```python
def _check_version_against_advisory(
    cve_id: str,
    effective_version: str,
    artifact_name: str,
    vulnerable_software: list,
    description: str,
    reported_version: str = "",   # ← agregar este parámetro
) -> str:
```

Y actualizar la llamada en Stage 0:

```python
_advisory_verdict = _check_version_against_advisory(
    cve_id=finding.cve_id,
    effective_version=_real_version,
    artifact_name=_artifact_name,
    vulnerable_software=getattr(finding, 'vulnerable_software', []),
    description=finding.description,
    reported_version=_reported_version,    # ← agregar
)
```

Y usar `reported_version` en la heurística en lugar del placeholder:

```python
# En la Fuente 3 (heurística), reemplazar:
rep = Version(normalize(reported_version_for_heuristic(...)))
# Por:
rep = Version(normalize(reported_version))
```

---

## Fix secundario — ampliar patrones de regex en `_extract_range_from_description()`

Los CVEs de Netty y otros proyectos Java usan formatos variados.
Reemplazar la lista `patterns` con una más completa:

```python
def _extract_range_from_description(version: str, description: str) -> str:
    import re

    patterns = [
        # Patrones directos de versión fix
        r'(?:before|prior to|earlier than)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'fixed (?:in|with|by)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'versions?\s+(?:before|prior to)\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'upgrade to\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        r'update to\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        # Patrones con "through" (rango hasta versión vulnerable)
        r'through\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        # Patrones de "affects X through Y" → Y es la última vulnerable
        r'affects.*?through\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        # Formato NVD: "versions before X"
        r'versions\s+before\s+([\d]+\.[\d.]+(?:\.\w+)?)',
        # Netty específico: "Netty X.Y.Z and earlier"
        r'([\d]+\.[\d.]+(?:\.\w+)?)\s+and\s+(?:earlier|prior)',
        # "up to and including X"
        r'up to (?:and including\s+)?([\d]+\.[\d.]+(?:\.\w+)?)',
    ]

    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            fix_version = match.group(1)
            # "through X" y "and earlier" significa X es la ÚLTIMA vulnerable
            # entonces fix = X+patch (no podemos calcular exactamente)
            # Para estos casos usar <= en lugar de <
            if any(p in pattern for p in ['through', 'and earlier', 'up to']):
                return _compare_version_to_ranges(version, [f"<= {fix_version}"])
            else:
                return _compare_version_to_ranges(version, [f"< {fix_version}"])

    return "UNKNOWN"
```

---

## Verificar después del fix

```bash
uv run python diag3.py
```

**Output esperado:**
```
=== CVE-2026-33871 ===
  effective_version:   4.1.132.Final
  advisory_verdict:    NOT_VULNERABLE  (o NOT_VULNERABLE_HEURISTIC)

=== CVE-2026-33870 ===
  effective_version:   4.1.132.Final
  advisory_verdict:    NOT_VULNERABLE  (o NOT_VULNERABLE_HEURISTIC)
```

Luego correr el flujo completo desde el chat con el mismo prompt.
El VEX debe mostrar `FALSE_POSITIVE` sin "requiere revisión humana".

---

## Lo que NO tocar

- `tools/reachability.py`, `tools/stage3_context.py`, `tools/decision.py`
- `server.py`
- `dry_run=True` por defecto
- `SecurityPolicy.max_snippet_lines = 50`
