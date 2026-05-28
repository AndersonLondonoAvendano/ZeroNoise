# Tarea 15 — Fix crítico: returns faltantes en Stage 0

**Archivo a modificar:** `zeronoise/tools/depcheck_gate.py`
**Tiempo estimado:** 5 minutos
**Dependencias:** Tarea 14 implementada

---

## Problema

Stage 0 detecta correctamente `FALSE_POSITIVE` pero no retorna.
Stage 2 corre después y sobreescribe el veredicto con `NOT_REACHABLE`.

```python
# Lo que está pasando:
if _advisory_verdict == "NOT_VULNERABLE":
    base["verdict"] = "FALSE_POSITIVE"   # ← se asigna
    base["justification"] = (...)
                                         # ← FALTA return base
# Stage 2 corre aquí y sobreescribe verdict con NOT_REACHABLE
```

---

## Fix

En `_analyze_finding()`, dentro del bloque Stage 0, buscar los DOS lugares
donde se asigna `base["verdict"] = "FALSE_POSITIVE"` y agregar `return base`
inmediatamente después del bloque de asignación en cada caso.

### Caso 1 — NOT_FOUND en artefacto Y árbol

```python
# ANTES:
if _av_nf and _tv_nf:
    base["verdict"] = "FALSE_POSITIVE"
    base["justification"] = (
        f"'{_artifact_name}' no está en el artefacto ni en el árbol "
        f"de dependencias runtime. Falso positivo del scanner."
    )
    # continúa ejecutando...

# DESPUÉS:
if _av_nf and _tv_nf:
    base["verdict"] = "FALSE_POSITIVE"
    base["justification"] = (
        f"'{_artifact_name}' no está en el artefacto ni en el árbol "
        f"de dependencias runtime. Falso positivo del scanner."
    )
    return base    # ← agregar esta línea
```

### Caso 2 — Versión efectiva fuera del rango vulnerable

```python
# ANTES:
if _advisory_verdict == "NOT_VULNERABLE":
    base["verdict"] = "FALSE_POSITIVE"
    base["justification"] = (
        f"La versión efectiva en runtime "
        f"({_artifact_name}@{_real_version}) no está en el rango "
        f"de versiones afectadas por {finding.cve_id}. "
        f"dep-check reportó el wrapper ({_reported_version}). "
        f"Resolución del árbol: {_resolution_note}"
    )
    # continúa ejecutando...

# DESPUÉS:
if _advisory_verdict == "NOT_VULNERABLE":
    base["verdict"] = "FALSE_POSITIVE"
    base["justification"] = (
        f"La versión efectiva en runtime "
        f"({_artifact_name}@{_real_version}) no está en el rango "
        f"de versiones afectadas por {finding.cve_id}. "
        f"dep-check reportó el wrapper ({_reported_version}). "
        f"Resolución del árbol: {_resolution_note}"
    )
    return base    # ← agregar esta línea
```

---

## Verificar

Buscar todos los `FALSE_POSITIVE` en `_analyze_finding()` y confirmar que
cada uno tiene `return base` inmediatamente después:

```powershell
Get-Content "C:\Users\admin\Desktop\ZeroNoise\zeronoise\tools\depcheck_gate.py" | `
    Select-String -Pattern "FALSE_POSITIVE|return base" -Context 1
```

Cada `FALSE_POSITIVE` debe estar seguido en las próximas 1-2 líneas por `return base`.

---

## Lo que NO tocar

Todo lo demás en el archivo — solo agregar los dos `return base`.
