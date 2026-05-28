# CLAUDE.md

@./README.md 
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

# POC Stage 3 — Context assembly (sin LLM, dry-run)
uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <ruta>

# POC Stage 3 — Con análisis LLM (requiere ANTHROPIC_API_KEY en .env)
uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <ruta> --analyze

# POC Stage 3 — Paquete único (sin DT, útil para debugging)
uv run python scripts/poc_stage3.py --project-path <ruta> --package adm-zip \
    --vuln-id CVE-2018-1002204 --severity HIGH \
    --description "Path traversal in extractAllTo()" --analyze

# POC Stage 3 — Pipeline completo con write-back a DT
uv run python scripts/poc_stage3.py --project-uuid <uuid> --project-path <ruta> \
    --analyze --apply

# POC Stage 0 — Verificación de artefacto y árbol de dependencias (standalone)
uv run python scripts/poc_artifact_verify.py \
    --project-path <ruta-al-proyecto>

# POC Stage 0 — Paquete específico
uv run python scripts/poc_artifact_verify.py \
    --project-path <ruta> \
    --package thymeleaf \
    --reported-version 3.4.6

# POC Stage 0 — Contra reporte dep-check completo
uv run python scripts/poc_artifact_verify.py \
    --project-path <ruta> \
    --report <ruta>/dependency-check-report.json

# POC Dep-Check Gate — solo diagnóstico del reporte (sin correr stages)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --diagnose-only

# POC Dep-Check Gate — análisis completo (dry-run)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente

# POC Dep-Check Gate — con threshold personalizado
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --cvss-threshold 9.0

# POC Dep-Check Gate — aplicar verdicts en DT (escritura real)
uv run python scripts/poc_depcheck.py \
    --report /ruta/dependency-check-report.json \
    --project-path /ruta/al/codigo/fuente \
    --apply

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
ANTHROPIC_API_KEY=<api-key-de-anthropic>   # Requerido para Stage 3 --analyze
STAGE3_CONFIDENCE_THRESHOLD=0.70           # Umbral mínimo para ejecutar Stage 3
# Seguridad — opcionales, tienen defaults razonables
MAX_FINDINGS_PER_RESPONSE=50        # Paginación defensiva en Stage 1
STAGE3_RATE_LIMIT_FETCH=200         # Rate limit para fetch_code_snippet por sesión
STAGE3_RATE_LIMIT_FUNCTION=100      # Rate limit para get_function_context por sesión
STAGE3_RATE_LIMIT_CALL=100          # Rate limit para get_call_context por sesión
STAGE3_RATE_LIMIT_SYMBOL=50         # Rate limit para find_symbol_usages por sesión
MCP_HOST=127.0.0.1                  # Solo relevante si MCP_TRANSPORT=sse
# OWASP Dependency-Check fast-gate
GATE_CVSS_THRESHOLD=7.0             # Umbral CVSS para el fast-gate (v3; v2 con flag de revisión humana)
```

El API Key se obtiene en DT: *Administration → Access Management → Teams → [tu equipo] → API Keys*.

---

## Estructura del Proyecto

```
zeronoise/
├── config.py                        # Settings con pydantic-settings (lee .env)
├── server.py                        # FastMCP server — registro central de tools + resources (17 tools)
├── audit.py                         # Decorator @audit_tool y @safe_tool — escribe audit.log (JSON-Lines)
├── models/
│   ├── vulnerability.py             # VerdictTaxonomy, AnalysisJustification, Finding, Evidence
│   ├── reachability.py              # ReachabilityResult, ImportUsage, ReproducibilityMetadata
│   ├── security_policy.py           # SecurityPolicy — límites de acceso a filesystem
│   ├── depcheck_finding.py          # PurlConfidence, CvssSource, DepCheckCvss, AffectedPackage, DepCheckFinding
│   └── artifact_finding.py          # Stage 0: VersionVerdict, ArtifactVersion, VersionVerification
├── clients/
│   ├── dependency_track.py          # Cliente httpx async para la API REST de DT
│   └── depcheck_ingester.py         # DepCheckIngester — lee/normaliza reporte JSON de OWASP Dep-Check
├── analyzers/
│   ├── base_scanner.py              # Abstract ImportScanner (multi-language architecture)
│   ├── scanner_factory.py           # Language detection (PURL/markers) + factory get_scanner()
│   ├── js_import_scanner.py         # Scanner JS/TS: require, import, dynamic import, side-effect
│   ├── java_import_scanner.py       # Scanner Java/Kotlin: import, import static, wildcard; Maven GAV/PURL
│   ├── artifact_inspector.py        # Stage 0: ArtifactInspector — BuildTool detection + fat JAR inspection
│   ├── dependency_tree_parser.py    # Stage 0: DependencyTreeParser — Maven/Gradle dep tree, starter resolution
│   └── project_context_reader.py    # ProjectContextReader — lee README, build config, YAML para Stage 3
└── tools/
    ├── sbom_ingestion.py            # MCP tools Stage 1 (list_projects, get_findings, etc.)
    ├── reachability.py              # MCP tools Stage 2 (run_reachability_filter, etc.)
    ├── stage3_context.py            # MCP tool Stage 3: prepare_stage3_context
    ├── code_context.py              # MCP tools Stage 3: fetch_code_snippet, find_symbol_usages, etc.
    ├── decision.py                  # MCP tools decision: generate_finding_verdict, generate_vex_report
    ├── depcheck_gate.py             # MCP tool: analyze_depcheck_report — fast-gate OWASP Dep-Check
    ├── dt_background.py             # MCP tool: analyze_project_vulnerabilities — pipeline Stage 0+2+3 desde DT
    └── _validators.py               # Validación compartida de inputs (UUID, paths, CVE IDs, etc.)

scripts/
├── poc_stage1.py                    # POC Stage 1: valida conexión con DT y tools
├── poc_stage2.py                    # POC Stage 2: reachability sobre fuente local
├── poc_stage3.py                    # POC Stage 3: context assembly + LLM analysis + VEX
├── poc_depcheck.py                  # POC Dep-Check Gate: analyze_depcheck_report
└── poc_artifact_verify.py           # POC Stage 0: verificación de artefacto y árbol de dependencias

main.py                              # Entrypoint: arranca el MCP server
audit.log                            # Log de ejecuciones de tools (JSON-Lines, auto-generado)
.env                                 # Credenciales (no commitear)
.env.example                         # Plantilla de variables de entorno
pyproject.toml                       # Deps: fastmcp, httpx, anthropic, pydantic-settings, packaging
```

---

## Arquitectura de 4 Stages

### Stage 0 — Artifact Version Verification ✅ IMPLEMENTADO

**Objetivo:** Verificar que la versión reportada por OWASP Dependency-Check coincide con la versión real del componente — tanto en el fat JAR compilado como en el árbol de dependencias resuelto. Detecta mismatches y starters antes de que el finding entre a Stage 2.

**Archivos clave:**
- `zeronoise/models/artifact_finding.py` — `VersionVerdict`, `ArtifactVersion`, `VersionVerification`
- `zeronoise/analyzers/artifact_inspector.py` — `ArtifactInspector`, `BuildTool`
- `zeronoise/analyzers/dependency_tree_parser.py` — `DependencyTreeParser`

#### ArtifactInspector

Inspecciona el fat JAR compilado del proyecto.

**Detección de build tool (`detect_build_tool()`):**

| Marcador en raíz | Build tool | Directorio canónico del JAR |
|---|---|---|
| `pom.xml` | `BuildTool.MAVEN` | `target/` |
| `build.gradle` / `build.gradle.kts` / `settings.gradle*` | `BuildTool.GRADLE` | `build/libs/` |
| (ninguno) | `BuildTool.UNKNOWN` | prueba `target/` y `build/libs/` |

**Cómo funciona:**
- `find_artifact()` localiza el fat JAR más reciente. Excluye `*-plain.jar` y `*-sources.jar`.
- `build_jar_index()` abre el ZIP e indexa `BOOT-INF/lib/`, `WEB-INF/lib/`, `lib/`. Lee `pom.properties` dentro de cada JAR anidado para la versión canónica.
- `verify_version(name, version)` compara versión reportada vs real en el JAR.
- `_versions_equal()` normaliza qualifiers (`.Final`, `.RELEASE`, `.GA`, `.SP\d+`).

#### DependencyTreeParser

Parsea el árbol de dependencias Maven/Gradle para obtener la versión efectivamente resuelta.

**Fuentes en orden de prioridad:**
1. `dep-tree.txt` en la raíz del proyecto (pre-generado)
2. Generación automática: `mvn dependency:tree` o `gradle dependencies --configuration runtimeClasspath`
3. `UNVERIFIABLE` si ninguna fuente disponible

**Métodos clave:**
- `load_tree()` — carga/genera el árbol y lo cachea. Maneja UTF-16 de Gradle en Windows.
- `verify_version(name, version)` — verifica versión en el árbol; detecta starters de Spring Boot.
- `resolve_effective_version(name, version)` — resolución avanzada con búsqueda de sub-módulos relacionados.

**Tabla starter → librería real (50+ entradas):**
- `spring-boot-starter-thymeleaf` → `thymeleaf`
- `spring-boot-starter-web` → `spring-webmvc`
- `spring-boot-starter-data-jpa` → `hibernate-core`
- `spring-boot-starter-security` → `spring-security-core`
- `spring-cloud-starter-openfeign` → `feign-core`
- (y muchos más)

#### VersionVerdict — 5 posibles resultados

| Veredicto | Significado | Acción |
|---|---|---|
| `CONFIRMED` | Versión reportada == versión real | Continúa con la versión reportada |
| `MISMATCH` | Versión reportada != versión real | Re-evalúa CVE contra versión real |
| `NOT_FOUND` | El paquete no está en el runtime | Posible falso positivo |
| `UNVERIFIABLE` | Sin artefacto ni árbol disponible | Continúa sin verificación |
| `TRANSITIVELY_RESOLVED` | Versión viene de starter/transitiva | Documenta la resolución |

---

### Stage 1 — Metadata-First Filter ✅ IMPLEMENTADO

**Objetivo:** Obtener la lista de CVEs del proyecto desde Dependency-Track sin tocar el código fuente. Consumo de tokens: **cero**.

**Archivo clave:** `zeronoise/tools/sbom_ingestion.py`

**4 MCP Tools registrados:**

| Tool | Descripción |
|---|---|
| `list_projects` | Lista todos los proyectos en DT (paginado automáticamente) |
| `get_project_findings` | Todos los findings de un proyecto con componente + CVE + entry points |
| `get_actionable_findings` | Solo findings no suprimidos y no marcados `NOT_AFFECTED`/`FALSE_POSITIVE` |
| `get_vulnerability_detail` | Detalle raw de un CVE específico (source, CWEs, affected versions) |

---

### Stage 2 — Reachability Analysis ✅ IMPLEMENTADO

**Objetivo:** Determinar si el paquete vulnerable es realmente importado por el código fuente. Los que no lo son → `NOT_AFFECTED` automático. Consumo de tokens: **cero**.

**Lenguajes soportados:** JavaScript/TypeScript ✅ | Java (Spring/Maven/Gradle) ✅ | Kotlin ✅ | Python/Go/Rust ⏳

**4 MCP Tools registrados:**

| Tool | Descripción |
|---|---|
| `analyze_package_reachability` | Un paquete: devuelve veredicto + ubicaciones de uso |
| `build_project_import_graph` | Mapa completo `{archivo → [paquetes importados]}` del proyecto |
| `run_reachability_filter` | Corre el filtro sobre TODOS los actionable findings. `dry_run=True` por defecto |
| `update_finding_analysis` | Escribe un veredicto manual para un finding específico en DT |

---

### Stage 3 — Contextual Deep Dive ✅ IMPLEMENTADO

**Objetivo:** Para los findings que Stage 2 marcó como `REACHABLE`, la IA inspecciona fragmentos específicos del código. **Este es el único stage que consume tokens LLM.**

**Stage 3 Gate (CRÍTICO):** Stage 3 solo se ejecuta cuando:
- `verdict == REACHABLE`
- `evidence` no vacío
- `confidence >= stage3_confidence_threshold` (default `0.70`)

**5 MCP Tools registrados (Stage 3):**

| Tool | Descripción |
|---|---|
| `prepare_stage3_context` | Ensambla context bundle completo (zero tokens) |
| `fetch_code_snippet` | Devuelve líneas específicas de un archivo (bounded) |
| `get_function_context` | Localiza la definición de una función y devuelve su cuerpo |
| `get_call_context` | Encuentra call sites de una función con contexto ±3 líneas |
| `find_symbol_usages` | Busca usages de un símbolo en todo el proyecto (capped a 100) |

**2 Tools de decisión:**

| Tool | Descripción |
|---|---|
| `generate_finding_verdict` | Produce el registro canónico de veredicto con Stage 3 gate evaluation |
| `generate_vex_report` | Genera reporte OpenVEX con `pipeline_decision: BLOCK \| PROMOTE` |

---

### Fast-Gate Tools ✅ IMPLEMENTADO

**2 MCP Tools orquestadoras** que ejecutan el pipeline completo (Stage 0 → 2 → 3):

#### `analyze_depcheck_report` (depcheck_gate.py)

Consume el reporte JSON de OWASP Dependency-Check directamente.

```
Input:  report_path, project_path, cvss_threshold (opcional), dry_run=True
Output: {pipeline_decision: BLOCK|PROMOTE, summary, verdicts[], vex_report, block_reason}
```

Flujo interno:
1. `DepCheckIngester.load()` — parsea y deduplica findings del reporte JSON
2. Filtra por `GATE_CVSS_THRESHOLD` (default 7.0)
3. Stage 0: `DependencyTreeParser + ArtifactInspector` — verifica versión real; si la versión real NO es vulnerable → `FALSE_POSITIVE`
4. Stage 2: `ImportScanner` — si el paquete no está importado → `NOT_REACHABLE`
5. Stage 3 heurístico: detecta señales de riesgo (`near_user_input`, `sanitization_present`) → `LIKELY_EXPLOITABLE` o `REACHABLE`
6. Genera VEX report con todos los verdicts

#### `analyze_project_vulnerabilities` (dt_background.py)

Equivalente al anterior pero consumiendo desde DT API.

```
Input:  project_uuid, project_path, severity_filter="HIGH", dry_run=True
Output: {pipeline_decision: BLOCK|PROMOTE, summary, verdicts[], vex_report}
```

Flujo interno:
1. Stage 1: `get_actionable_findings(project_uuid)` — obtiene findings de DT
2. Filtra por `severity_filter` (CRITICAL | HIGH | MEDIUM | ALL)
3. Stage 0 + 2 + 3 (mismo pipeline que `analyze_depcheck_report`)
4. Enriquece Stage 3 con `ProjectContextReader` (README, build config, YAML de la app)
5. Si `dry_run=False`: escribe verdicts en DT vía `update_finding_analysis`

---

## Flujo Completo

```
── Frente 1: Dependency-Track ──────────────────────────────
DT API → Stage 1 → filtro severidad
                 ↓
         Stage 0 (versión JAR + dep-tree)
          ├── MISMATCH/NOT_FOUND → FALSE_POSITIVE
          └── CONFIRMED          → Stage 2
                 ↓
         Stage 2 (scan source)
          ├── NOT imported → NOT_AFFECTED (0 tokens)
          └── Imported     → Stage 3
                 ↓
         Stage 3 (heurístico + LLM opcional)
          ├── Not exploitable → FALSE_POSITIVE + VEX
          └── Exploitable     → EXPLOITABLE + BLOCK

── Frente 2: OWASP Dep-Check ───────────────────────────────
dep-check.json → filtro CVSS ≥ threshold
                 ↓
         Stage 0 (versión JAR + dep-tree)
         Stage 2 (scan source)
         Stage 3 (señales heurísticas)
                 ↓
         pipeline_decision: BLOCK | PROMOTE
```

---

## Decisiones de Diseño Importantes

- **`server.py` es el registro central.** Al agregar tools, solo se añaden líneas `mcp.tool()(nueva_tool)` ahí.
- **`fastmcp.Client(mcp)` en los POC** ejecuta el servidor en proceso — no levanta subproceso ni puerto.
- **`dry_run=True` por defecto** en todas las tools de escritura — nunca escribe en DT sin confirmación explícita.
- **El scan de Stage 2 es síncrono** dentro de funciones `async` porque el I/O de disco es local.
- **`isSuppressed: false`** en todos los verdicts — los findings permanecen visibles y auditables en DT.
- **Stage 0 nunca interrumpe el flujo** — un `UNVERIFIABLE` (sin artefacto compilado) deja pasar el finding a Stage 2.
- **`DepCheckIngester` es tolerante** — maneja 6 casos de normalización (PURL presente/ausente, CVSS v2 fallback, fat JAR shadeado, deduplicación de CVEs, etc.).

---

## Seguridad Implementada ✅

Todos los controles de seguridad están implementados. No modificar sin entender sus invariantes.

### Confidencialidad

| Control | Archivo clave | Descripción |
|---|---|---|
| **Path traversal prevention** | `tools/code_context.py`, `tools/_validators.py` | `_safe_resolve()` rechaza `..`, `~`, null bytes, shell chars y directorios sensibles del sistema |
| **Sanitización de outputs** | `tools/code_context.py` | `_mark_code_output()` agrega `type: "code_snippet"` + `warning` → el LLM los trata como datos, no instrucciones |
| **Enmascaramiento en audit.log** | `audit.py` | `_mask_sensitive()` redacta valores de `api_key`, `token`, `password`, `secret` |
| **Permisos restrictivos audit.log** | `main.py` | `chmod 0o600` al arrancar (best-effort en Windows) |

### Integridad

| Control | Archivo clave | Descripción |
|---|---|---|
| **Validación de inputs** | `tools/_validators.py` + todas las tools | UUID v4, path absoluto/existente, file_path sin traversal, package_name ≤200 chars, formato CVE/GHSA, rangos de líneas 1–100000 |
| **Inmutabilidad de verdicts** | `tools/reachability.py` | Jerarquía `NOT_SET→IN_TRIAGE→NOT_AFFECTED/FALSE_POSITIVE→EXPLOITABLE`; `_can_overwrite()` impide regresiones |
| **Hash de integridad VEX** | `tools/decision.py` | `_add_vex_integrity()` embebe SHA-256 del reporte |
| **Rate limiting** | `tools/code_context.py` | Contadores por sesión con `threading.Lock`; límites: 200/100/100/50 invocaciones |

### Disponibilidad

| Control | Archivo clave | Descripción |
|---|---|---|
| **Timeouts httpx** | `clients/dependency_track.py` | `Timeout(connect=5s, read=30s, write=10s, pool=5s)` |
| **`@safe_tool` decorator** | `audit.py` | `ValueError`/`TypeError` → `{"error": "validation_error"}`; otros → traceback en `audit.log` |
| **Paginación defensiva** | `tools/sbom_ingestion.py` | `offset` param + `has_more`/`next_offset`; máx `MAX_FINDINGS_PER_RESPONSE` por llamada |
| **Fail-fast al arranque** | `main.py` | `_startup_security_checks()`: avisa SSE en `0.0.0.0`, corrige `audit.log` world-writable |

### Orden de decoradores en las tools

```python
@safe_tool          # ← afuera: captura excepciones, nunca crashea el servidor MCP
@audit_tool(side_effects="none")  # ← adentro: registra siempre en audit.log
async def mi_tool(...):
    ...
```
