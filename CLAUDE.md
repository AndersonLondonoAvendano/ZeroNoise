# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Project Overview

**ZeroNoise** es un motor de auditoría inteligente de vulnerabilidades que elimina falsos positivos. En lugar de reportar todas las vulnerabilidades encontradas en dependencias, determina si son **realmente explotables** en el contexto específico del proyecto usando IA y MCP (Model Context Protocol).

**Filosofía central:** La IA no lee todo el código; pregunta solo por lo que necesita saber.

**Infraestructura de pruebas activa:**
- Dependency-Track UI: `http://localhost:8081`
- Dependency-Track API Server: `http://localhost:8080`
- Proyecto de prueba en DT: `nodejs-goof` (UUID: `ad5f9c55-f3e2-4684-844f-5c2300e3a9c8`)

---

## Commands

```bash
# Instalar dependencias
uv sync

# Correr el servidor MCP (modo stdio por defecto)
uv run python main.py

# POC Stage 1 — Metadata-First Filter
uv run python scripts/poc_stage1.py --project-uuid <uuid>

# POC Stage 2 — Reachability Analysis (dry-run, no escribe en DT)
uv run python scripts/poc_stage2.py --project-uuid <uuid> --project-path <ruta-al-fuente>

# POC Stage 2 — con un paquete específico
uv run python scripts/poc_stage2.py --project-path <ruta> --package adm-zip

# POC Stage 2 — aplicar verdicts NOT_AFFECTED en DT (escritura real)
uv run python scripts/poc_stage2.py --project-uuid <uuid> --project-path <ruta> --apply

# Añadir dependencia
uv add <package>
```

---

## Configuración (.env)

Crear `.env` en la raíz (ver `.env.example`). La variable `DT_API_KEY` es **obligatoria** — sin ella el proceso falla al arrancar porque `pydantic-settings` la valida.

```env
DT_BASE_URL=http://localhost:8080
DT_API_KEY=<api-key-de-dependency-track>
MCP_SERVER_NAME=zeronoise
MCP_TRANSPORT=stdio   # stdio | sse
```

El API Key se obtiene en DT: *Administration → Access Management → Teams → [tu equipo] → API Keys*.

---

## Estructura del Proyecto

```
zeronoise/
├── config.py                        # Settings con pydantic-settings (lee .env)
├── server.py                        # FastMCP server — registro central de tools por stage
├── models/
│   ├── vulnerability.py             # Modelos Stage 1: Project, Component, Vulnerability, Finding
│   └── reachability.py             # Modelos Stage 2: ReachabilityResult, ImportUsage
├── clients/
│   └── dependency_track.py         # Cliente httpx async para la API REST de DT
├── analyzers/
│   └── js_import_scanner.py        # Scanner estático JS/TS (regex, sin AST)
└── tools/
    ├── sbom_ingestion.py            # MCP tools de Stage 1
    └── reachability.py             # MCP tools de Stage 2

scripts/
├── poc_stage1.py                   # POC Stage 1: valida conexión con DT y tools
└── poc_stage2.py                   # POC Stage 2: reachability sobre fuente local

main.py                             # Entrypoint: arranca el MCP server
.env                                # Credenciales (no commitear)
.env.example                        # Plantilla de variables de entorno
pyproject.toml                      # Deps: fastmcp>=3.2.4, httpx>=0.28.1 | build: hatchling
```

---

## Arquitectura de 3 Stages

### Stage 1 — Metadata-First Filter ✅ IMPLEMENTADO

**Objetivo:** Obtener la lista de CVEs del proyecto desde Dependency-Track sin tocar el código fuente. Identificar el componente vulnerable, su severidad, y si el advisory incluye entry points (funciones/clases específicas). Consumo de tokens: **cero**.

**Archivo clave:** `zeronoise/tools/sbom_ingestion.py`

**4 MCP Tools registrados:**

| Tool | Descripción |
|---|---|
| `list_projects` | Lista todos los proyectos en DT (paginado automáticamente) |
| `get_project_findings` | Todos los findings de un proyecto con componente + CVE + entry points |
| `get_actionable_findings` | Solo findings no suprimidos y no marcados `NOT_AFFECTED`/`FALSE_POSITIVE` |
| `get_vulnerability_detail` | Detalle raw de un CVE específico (source, CWEs, affected versions) |

**Gate crítico:** `Finding.requires_reachability_check` en `models/vulnerability.py` — filtra los findings que ya tienen un veredicto en DT para no reprocesarlos.

**Resultado validado con `nodejs-goof`:**
- 267 findings totales, 267 actionables
- Los advisories de GitHub/OSV no incluyen `vulnerable_functions` (lista vacía) — esto es normal y esperado. La extracción de entry points es best-effort.

---

### Stage 2 — Reachability Analysis ✅ IMPLEMENTADO

**Objetivo:** Determinar si el paquete vulnerable es realmente importado (`require`/`import`) por el código fuente de la aplicación. Los que no lo son → `NOT_AFFECTED` automático. Consumo de tokens: **cero**.

**Limitación actual:** Solo soporta proyectos **JavaScript/TypeScript** (extensiones `.js .mjs .cjs .ts .tsx .jsx`). Para Python, Java, Go, etc. se necesitarían nuevos scanners en `zeronoise/analyzers/`.

**Archivos clave:**
- `zeronoise/analyzers/js_import_scanner.py` — lógica de escaneo
- `zeronoise/tools/reachability.py` — MCP tools
- `zeronoise/models/reachability.py` — `ReachabilityResult` con `auto_justification`

**Cómo funciona el scanner (`js_import_scanner.py`):**
- Recorre recursivamente todos los archivos fuente ignorando: `node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`, `out`
- Detecta 4 patrones: `require('pkg')`, `import ... from 'pkg'`, `import('pkg')`, `import 'pkg'` (side-effect)
- Soporta scoped packages (`@scope/pkg`)
- Acepta nombre de paquete o PURL (`pkg:npm/adm-zip@0.4.7`)
- Resultado: `ReachabilityResult` con lista de `ImportUsage` (archivo, línea, statement)
- **Optimización:** `run_reachability_filter` cachea el scan por paquete — si `adm-zip` tiene 5 CVEs, solo escanea una vez

**4 MCP Tools registrados:**

| Tool | Descripción |
|---|---|
| `analyze_package_reachability` | Un paquete: devuelve veredicto + ubicaciones de uso |
| `build_project_import_graph` | Mapa completo `{archivo → [paquetes importados]}` del proyecto |
| `run_reachability_filter` | Corre el filtro sobre TODOS los actionable findings. `dry_run=True` por defecto |
| `update_finding_analysis` | Escribe un veredicto manual para un finding específico en DT |

**Cómo se escribe NOT_AFFECTED en Dependency-Track:**

`DependencyTrackClient.update_analysis()` hace `PUT /api/v1/analysis` con:
```json
{
  "project": "<project_uuid>",
  "component": "<component_uuid>",
  "vulnerability": "<vulnerability_uuid>",
  "analysisState": "NOT_AFFECTED",
  "analysisJustification": "CODE_NOT_REACHABLE",
  "analysisDetails": "[ZeroNoise Stage 2] Package 'adm-zip' is installed as a dependency but is never imported..."
}
```
En la UI de DT esto aparece en la pestaña **Audit Trail / Analysis** del finding con el texto de `analysisDetails` como comentario de auditoría. El finding permanece visible (no suprimido) para que sea auditable.

---

### Stage 3 — Contextual Deep Dive ⏳ PENDIENTE

**Objetivo:** Para los findings que Stage 2 marcó como `REACHABLE`, la IA usa MCP tools para inspeccionar fragmentos específicos del código: ¿están las entradas sanitizadas? ¿cuál es el entorno de ejecución? ¿hay controles de red/permisos? Este es el único stage que consume tokens LLM.

**Próximos pasos a implementar:**
- MCP tool: `fetch_code_snippet(project_path, file, start_line, end_line)` — obtiene el fragmento de código donde se usa el paquete
- MCP tool: `get_call_context(project_path, file, function_name)` — obtiene el contexto de llamada de la función
- MCP tool: `generate_vex_report(findings)` — genera el archivo VEX final para CI/CD gating
- Soporte multi-lenguaje en Stage 2 (agregar `py_import_scanner.py`, etc.)

---

## Flujo Completo (Stage 1 → Stage 2 → Stage 3)

```
DT API → Stage 1 (list findings) → 267 actionable findings
                ↓
         Stage 2 (scan source)
          ├── NOT imported → NOT_AFFECTED → escrito en DT (0 tokens)
          └── Imported     → REACHABLE   → pasa a Stage 3
                ↓
         Stage 3 (AI inspects code snippets)
          ├── Not exploitable → FALSE_POSITIVE + VEX generado
          └── Exploitable     → EXPLOITABLE  + pipeline bloqueado
```

---

## Decisiones de Diseño Importantes

- **`server.py` es el registro central.** Al agregar Stage 3, solo se añaden líneas `mcp.tool()(nueva_tool)` ahí, sin modificar nada más.
- **`fastmcp.Client(mcp)` en los POC** ejecuta el servidor en proceso — no se levanta un subproceso ni se abre un puerto. Esto es posible porque fastmcp acepta una instancia `FastMCP` directamente como transport.
- **`dry_run=True` por defecto** en `run_reachability_filter` — nunca escribe en DT sin confirmación explícita.
- **El scan de Stage 2 es síncrono** dentro de funciones `async` porque el I/O de disco es local. Si en el futuro se escala a repositorios remotos, se deberá usar `asyncio.to_thread()`.
- **`isSuppressed: false`** en todos los verdicts — los findings permanecen visibles y auditables en DT, solo cambia su estado de análisis.
