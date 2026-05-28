# Tarea 18 — Unificar Stage 0 en el frente DT + output en español

**Archivos a modificar:**
- `zeronoise/tools/dt_background.py` — agregar Stage 0 al flujo DT
- `zeronoise/tools/depcheck_gate.py` — extraer Stage 0 como función reutilizable
- `zeronoise/tools/reachability.py` — justificaciones en español
- `zeronoise/tools/decision.py` — justificaciones en español

**Tiempo estimado:** 35 minutos
**Dependencias:** Tareas 13, 14, 16, 17 implementadas

---

## Problema 1 — Stage 0 solo existe en el frente dep-check

### Estado actual

```
FRENTE DEP-CHECK (depcheck_gate.py):
  Stage 0 → árbol + artefacto + advisory → FALSE_POSITIVE / VULNERABLE
  Stage 2 → reachability (imports)
  Stage 3 → LLM contextual

FRENTE DT (dt_background.py):
  Stage 1 → get_actionable_findings desde DT API
  Stage 2 → reachability (imports)          ← sin Stage 0
  Stage 3 → LLM contextual                  ← sin contexto del proyecto
```

### Lo que falta en el frente DT

Cuando el equipo le pregunta al agente de Teams por las vulns de un proyecto
en DT, ZeroNoise debería también:
- Verificar la versión efectiva en el árbol de dependencias
- Cruzar con el advisory del CVE
- Usar el ArtifactInspector como fallback
- Leer el README y build.gradle para contexto del LLM

---

## Fix 1 — Extraer Stage 0 como función reutilizable

En `depcheck_gate.py`, el bloque Stage 0 está inline en `_analyze_finding()`.
Extraerlo a una función standalone que ambos frentes puedan usar.

**Crear en `depcheck_gate.py`** (o en un nuevo archivo
`zeronoise/analyzers/stage0_verifier.py` si se prefiere separación):

```python
async def run_stage0(
    artifact_name: str,
    reported_version: str,
    cve_id: str,
    vulnerable_software: list,
    description: str,
    cwes: list,
    project_path: str,
) -> dict:
    """
    Stage 0: Verificación de versión real antes de Stage 2.

    Reutilizable por ambos frentes (dep-check y DT).

    Returns:
        {
          "verdict": "FALSE_POSITIVE" | "VULNERABLE" | "UNKNOWN" | None,
          "justification": str,
          "real_version": str | None,
          "version_source": str,
          "resolution_note": str,
          "version_is_vulnerable": bool,
          "requires_human_review": bool,
          "skip_stage2": bool,   ← True si Stage 0 ya tiene veredicto definitivo
        }
    """
    from zeronoise.analyzers.artifact_inspector import ArtifactInspector
    from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser
    from zeronoise.models.artifact_finding import VersionVerdict

    result = {
        "verdict": None,
        "justification": "",
        "real_version": None,
        "version_source": "unknown",
        "resolution_note": "",
        "version_is_vulnerable": False,
        "requires_human_review": False,
        "skip_stage2": False,
    }

    if not artifact_name or not reported_version:
        return result

    tree_parser = DependencyTreeParser(project_path)
    artifact_inspector = ArtifactInspector(project_path)

    # Tres niveles de resolución de versión
    effective_version, resolution_note = tree_parser.resolve_effective_version(
        artifact_name, reported_version
    )
    av = artifact_inspector.verify_version(artifact_name, reported_version)

    if effective_version:
        real_version = effective_version
        version_source = "dependency_tree"
    elif av and av.real_version:
        real_version = av.real_version
        version_source = "compiled_artifact"
        resolution_note = (
            f"Versión encontrada en el artefacto compilado: "
            f"{artifact_name}@{real_version}. "
            f"El árbol de dependencias no resolvió este artifact."
        )
    else:
        real_version = reported_version
        version_source = "depcheck_reported"
        resolution_note = (
            f"Usando versión reportada como referencia: "
            f"{artifact_name}@{real_version}."
        )

    result["real_version"] = real_version
    result["version_source"] = version_source
    result["resolution_note"] = resolution_note

    # CASO 1: NOT_FOUND en árbol Y artefacto → falso positivo del scanner
    av_nf = av and av.verdict == VersionVerdict.NOT_FOUND
    tv_nf = effective_version is None and "no encontrado" in resolution_note.lower()
    if av_nf and tv_nf:
        result["verdict"] = "FALSE_POSITIVE"
        result["justification"] = (
            f"'{artifact_name}' no está empaquetado en el artefacto final "
            f"ni en el árbol de dependencias runtime. "
            f"Falso positivo del scanner — paquete no presente en el classpath real."
        )
        result["skip_stage2"] = True
        return result

    # CASO 2: Cruzar versión con el advisory del CVE
    if real_version:
        advisory_verdict = _check_version_against_advisory(
            cve_id=cve_id,
            effective_version=real_version,
            artifact_name=artifact_name,
            vulnerable_software=vulnerable_software,
            description=description,
            reported_version=reported_version,
        )

        if advisory_verdict == "NOT_VULNERABLE":
            result["verdict"] = "FALSE_POSITIVE"
            result["justification"] = (
                f"La versión efectiva en runtime "
                f"({artifact_name}@{real_version}, fuente: {version_source}) "
                f"no está en el rango de versiones afectadas por {cve_id}. "
                f"{resolution_note}"
            )
            result["skip_stage2"] = True
            return result

        elif advisory_verdict == "VULNERABLE":
            result["version_is_vulnerable"] = True
            result["verdict"] = "VULNERABLE_IN_RUNTIME"
            result["justification"] = (
                f"ATENCIÓN: {artifact_name}@{real_version} "
                f"ESTÁ en el rango vulnerable de {cve_id}. "
                f"Fuente: {version_source}. "
                f"Continuar con análisis de alcanzabilidad."
            )

    return result
```

---

## Fix 2 — Integrar `run_stage0()` en `dt_background.py`

En `analyze_project_vulnerabilities()`, dentro del bucle de findings,
agregar Stage 0 ANTES de Stage 2. El finding de DT tiene los datos
necesarios en su estructura:

```python
# En el bucle for finding in to_analyze:, ANTES del bloque Stage 2:

component = finding.get("component", {})
vuln = finding.get("vulnerability", {})
purl = component.get("purl", "")
cve_id = vuln.get("vulnId", "")

# Extraer artifact_name y version del PURL
# pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final
# → artifact_name = "netty-resolver-dns", version = "4.1.128.Final"
_artifact_name, _reported_version = _parse_purl(purl)

# Extraer vulnerable_software de DT si está disponible
# DT tiene esta info en el detalle del CVE
_vulnerable_software = vuln.get("affectedVersions", []) or []
_cwes = [c.get("cweId", "") for c in vuln.get("cwes", [])]
_description = vuln.get("description", "")

# ── Stage 0 ──────────────────────────────────────────────────────────
from zeronoise.tools.depcheck_gate import run_stage0

_stage0 = await run_stage0(
    artifact_name=_artifact_name,
    reported_version=_reported_version,
    cve_id=cve_id,
    vulnerable_software=_vulnerable_software,
    description=_description,
    cwes=_cwes,
    project_path=project_path,
)

entry["version_verification"] = {
    "real_version": _stage0["real_version"],
    "version_source": _stage0["version_source"],
    "resolution_note": _stage0["resolution_note"],
}

if _stage0["skip_stage2"]:
    entry["verdict"] = _stage0["verdict"]
    entry["justification"] = _stage0["justification"]
    entry["requires_human_review"] = _stage0.get("requires_human_review", False)
    verdicts.append(entry)
    continue  # No ejecutar Stage 2 ni Stage 3

if _stage0["version_is_vulnerable"]:
    entry["version_note"] = _stage0["justification"]
# ── Fin Stage 0 ───────────────────────────────────────────────────────

# Stage 2 continúa aquí (código existente sin cambios)...
```

**Agregar función auxiliar** en `dt_background.py`:

```python
def _parse_purl(purl: str) -> tuple[str, str]:
    """
    Extrae artifact_name y version de un PURL Maven.
    pkg:maven/io.netty/netty-resolver-dns@4.1.128.Final
    → ("netty-resolver-dns", "4.1.128.Final")
    """
    if not purl:
        return "", ""
    try:
        # Formato: pkg:maven/groupId/artifactId@version
        parts = purl.split("/")
        artifact_at_version = parts[-1]  # "netty-resolver-dns@4.1.128.Final"
        if "@" in artifact_at_version:
            artifact, version = artifact_at_version.split("@", 1)
            return artifact, version
        return artifact_at_version, ""
    except Exception:
        return "", ""
```

---

## Fix 3 — Enriquecer Stage 3 del frente DT con contexto del proyecto

En `dt_background.py`, antes del bucle de findings, leer el contexto del
proyecto una sola vez:

```python
# Antes del for finding in to_analyze:
from zeronoise.analyzers.project_context_reader import ProjectContextReader

_proj_ctx = ProjectContextReader(project_path).read()
_proj_ctx_str = _proj_ctx.to_llm_context()
```

Y en la llamada a `prepare_stage3_context`, enriquecer el context bundle:

```python
context = await prepare_stage3_context(...)

if isinstance(context, dict):
    context["project_context"] = _proj_ctx_str
    if _proj_ctx.spring_boot_version:
        context["spring_boot_version"] = _proj_ctx.spring_boot_version
    if _proj_ctx.declared_boms:
        context["declared_boms"] = _proj_ctx.declared_boms
    if _proj_ctx.excluded_modules:
        context["excluded_modules"] = _proj_ctx.excluded_modules
```

---

## Fix 4 — Obtener vulnerable_software desde DT API

DT tiene el rango de versiones afectadas en su API. En `dt_background.py`,
enriquecer el finding con los datos del advisory antes de Stage 0:

```python
# Si el finding tiene vulnerability uuid, obtener el detalle
_vuln_uuid = vuln.get("uuid", "")
_vulnerable_software = []

if _vuln_uuid:
    try:
        from zeronoise.tools.sbom_ingestion import get_vulnerability_detail
        vuln_detail = await get_vulnerability_detail(
            vulnerability_uuid=_vuln_uuid
        )
        # DT retorna affectedVersionRanges o similar
        _vulnerable_software = vuln_detail.get("affectedVersionRanges", [])
        if not _vulnerable_software:
            # Intentar extraer de la descripción si no hay rangos estructurados
            _description = vuln_detail.get("description", _description)
    except Exception:
        pass  # Continuar sin datos del advisory
```

---

## Fix 5 — Output en español

### Justificaciones de Stage 2 en `reachability.py`

Buscar en `tools/reachability.py` las cadenas de texto que se escriben
en DT como `analysisDetails` y traducirlas al español:

```python
# ANTES:
"[ZeroNoise Stage 2] Package '{package}' is installed as a dependency "
"but is never imported in the project source code. "
"The vulnerability {cve_id} is not exploitable in this context."

# DESPUÉS:
"[ZeroNoise Stage 2] El paquete '{package}' está instalado como dependencia "
"pero nunca es importado en el código fuente del proyecto. "
"La vulnerabilidad {cve_id} no es explotable en este contexto."
```

### Justificaciones de Stage 3 en `decision.py`

Buscar el system prompt o las instrucciones que se pasan al LLM en Stage 3
y agregar la instrucción de idioma:

```python
# En el system prompt o en las analysis_instructions del context bundle:
# Agregar al inicio:
"IMPORTANTE: Todas las justificaciones, análisis y comentarios deben estar "
"escritos en español. Los nombres técnicos (CVE IDs, nombres de paquetes, "
"PURLs, CWEs) se mantienen en su formato original."
```

### Justificaciones de Stage 0 en `depcheck_gate.py`

Las justificaciones de `run_stage0()` ya están en español en el código
de esta tarea. Verificar que todas las cadenas en el archivo estén en español.

### Comentarios escritos en DT por `update_finding_analysis()`

En `tools/reachability.py`, buscar todas las llamadas a
`dt_client.update_analysis()` o `update_finding_analysis()` y verificar
que el campo `details` (que aparece en el Audit Trail de DT) esté en español.

```python
# En update_finding_analysis, el parámetro details:
# ANTES:
details = f"[ZeroNoise Stage 2] Package not reachable..."
# DESPUÉS:
details = f"[ZeroNoise Stage 2] Paquete no alcanzable desde el código fuente..."
```

---

## Cómo verificar después del fix

### Verificar que el frente DT ahora usa Stage 0

```bash
# Usar el prompt del frente DT con el proyecto clientes
# El veredicto de netty-resolver-dns debería decir FALSE_POSITIVE
# con la versión efectiva del árbol, igual que el frente dep-check
```

Prompt de prueba para el chat:

> Usa `analyze_project_vulnerabilities` con `project_uuid` =
> `0dd02b59-c900-4bdd-bfda-6539ec040562`,
> `project_path` = `C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes`,
> `severity_filter` = `HIGH`, `dry_run` = true.
> Los comentarios y justificaciones deben estar en español.

**Output esperado:**
```
CVE-2026-33871 → FALSE_POSITIVE
  Justificación: La versión efectiva en runtime (netty-resolver-dns@4.1.132.Final,
  fuente: dependency_tree) no está en el rango de versiones afectadas...
  [En español, sin "requires human review"]
```

Si el frente DT da el mismo resultado que el frente dep-check para el mismo
proyecto, la unificación está completa.

### Verificar idioma en DT

Con `dry_run=False` en un proyecto de prueba, verificar en la UI de DT
que el Audit Trail del finding muestra el comentario en español.

---

## Resumen de lo que cambia

| Componente | Antes | Después |
|---|---|---|
| `dt_background.py` | Stage 1 → Stage 2 → Stage 3 | Stage 1 → **Stage 0** → Stage 2 → Stage 3 |
| Árbol de dependencias | Solo frente dep-check | Ambos frentes |
| ArtifactInspector | Solo frente dep-check | Ambos frentes |
| ProjectContextReader | Solo frente dep-check | Ambos frentes |
| Advisory del CVE | Solo frente dep-check | Ambos frentes |
| Idioma de justificaciones | Inglés | Español |
| Comentarios en DT | Inglés | Español |

---

## Lo que NO tocar

- `tools/reachability.py` — solo cambiar strings de texto, no la lógica
- `tools/stage3_context.py` — no modificar
- `server.py` — no modificar
- `dry_run=True` por defecto — no cambiar
- `SecurityPolicy.max_snippet_lines = 50` — no cambiar
