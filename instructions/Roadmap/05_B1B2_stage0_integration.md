# Tarea 05 — B1+B2: Integración Stage 0 en depcheck_gate

**Archivo a modificar:** `zeronoise/tools/depcheck_gate.py`
**Tiempo estimado:** 15 minutos
**Dependencias:** Tareas 03 y 04 implementadas

---

## Qué hacer

Agregar un bloque "Stage 0" al inicio de la función `_analyze_finding()` en
`tools/depcheck_gate.py`. Este bloque corre ANTES de Stage 2 (reachability).

## El bloque a insertar

Buscar en `_analyze_finding()` la línea que dice:
```python
# Sin PURL → no se puede hacer reachability determinístico
if not finding.can_run_reachability:
```

**Insertar ANTES de esa línea:**

```python
# ── Stage 0: Verificación de versión real ─────────────────────────────
from zeronoise.analyzers.artifact_inspector import ArtifactInspector
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser

_artifact_inspector = ArtifactInspector(project_path)
_tree_parser = DependencyTreeParser(project_path)

_artifact_name = (
    finding.primary_package.artifact_name
    if finding.primary_package else ""
)
_reported_version = (
    finding.primary_package.artifact_version
    if finding.primary_package else ""
)

_av = None
_tv = None
_version_note = ""
_real_version = None

if _artifact_name and _reported_version:
    _av = _artifact_inspector.verify_version(_artifact_name, _reported_version)
    _tv = _tree_parser.verify_version(_artifact_name, _reported_version)

    # Tomar la versión real de la fuente más confiable
    if _tv and _tv.real_version:
        _real_version = _tv.real_version
        _version_note = _tv.analysis_note
    elif _av and _av.real_version:
        _real_version = _av.real_version
        _version_note = _av.analysis_note

    # Adjuntar al output
    base["version_verification"] = {
        "artifact": _av.summary if _av else "No verificado",
        "tree": _tv.summary if _tv else "No verificado",
        "real_version": _real_version,
        "requires_reanalysis": (
            (_av and _av.requires_reanalysis) or
            (_tv and _tv.requires_reanalysis)
        ),
    }
    if _version_note:
        base["version_note"] = _version_note

    # NOT_FOUND en ambas fuentes → falso positivo del scanner
    from zeronoise.models.artifact_finding import VersionVerdict
    _av_not_found = _av and _av.verdict == VersionVerdict.NOT_FOUND
    _tv_not_found = _tv and _tv.verdict == VersionVerdict.NOT_FOUND
    if _av_not_found and _tv_not_found:
        base["verdict"] = "FALSE_POSITIVE"
        base["justification"] = (
            f"'{_artifact_name}' no está empaquetado en el artefacto final "
            f"ni en el árbol de dependencias runtime. "
            f"El scanner reportó una versión que no existe en el classpath real."
        )
        return base
# ── Fin Stage 0 ───────────────────────────────────────────────────────
```

## Pasar version_note a Stage 3

En la llamada existente a `prepare_stage3_context`, después de obtener `context`,
agregar el note si existe:

```python
context = await prepare_stage3_context(...)

# Agregar version_note al context para que el LLM lo considere
if _version_note and isinstance(context, dict):
    context["version_verification_note"] = _version_note
    if _real_version:
        context["real_version"] = _real_version
```

## Verificar

```bash
uv run python scripts/poc_depcheck.py \
    --report C:\Users\admin\Desktop\ZeroNoise\dependency-check-report.json \
    --project-path C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes \
    --diagnose-only
```

El output de cada CVE debe mostrar ahora el campo `version_verification`.

## Lo que NO tocar

La lógica de Stage 2 y Stage 3 existente — solo agregar el bloque antes, no modificar lo que sigue.
