# ZeroNoise — Documentación Técnica

> **Propósito de este documento:** Explicar cómo funciona ZeroNoise desde adentro: arquitectura, flujo de datos, tools MCP, modelos de datos, integraciones actuales y roadmap técnico.

---

## ¿Qué problema resuelve?

Un escáner SCA estándar (como Dependency-Track) reporta una vulnerabilidad cuando una librería vulnerable está en el `pom.xml` o `package.json`, **sin importar si esa librería se usa realmente**. En proyectos medianos, esto genera 200-300 findings por sprint, de los cuales el 80-90% son falsos positivos.

ZeroNoise actúa como un **segundo filtro inteligente**: recibe esos findings y determina, con evidencia de código fuente, si la vulnerabilidad es realmente explotable en **este proyecto específico**.

---

## Filosofía de diseño

```
"La IA no debe leer todo el código — debe preguntar solo por lo que necesita."
```

Esto se traduce en tres principios de implementación:

1. **Cero tokens en Stage 1 y Stage 2.** Todo el análisis de metadatos e importaciones es determinístico y no consume la API de LLM.
2. **Evidencia antes de tokens.** Stage 3 (LLM) solo se ejecuta si existe evidencia de reachability con confianza ≥ 0.70.
3. **Acceso quirúrgico al código.** El LLM nunca recibe archivos completos — solo snippets acotados por `SecurityPolicy.max_snippet_lines` (50 líneas).

---

## Arquitectura general

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PIPELINE ZERONOISE                            │
│                                                                         │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │   STAGE 1    │    │    STAGE 2       │    │       STAGE 3         │  │
│  │  Metadata    │───▶│  Reachability    │───▶│  Contextual Analysis  │  │
│  │   Filter     │    │   Analysis       │    │     (LLM + MCP)       │  │
│  └──────────────┘    └──────────────────┘    └───────────────────────┘  │
│         │                    │                          │                │
│    0 tokens LLM         0 tokens LLM            Tokens LLM aquí         │
│    API DT + modelos      Regex estático          (solo para REACHABLE)   │
│                                                          │                │
│                                                 ┌────────▼──────────┐    │
│                                                 │  DECISION ENGINE  │    │
│                                                 │  Verdict + VEX    │    │
│                                                 └───────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Estructura de archivos

```
zeronoise/
├── config.py                    # Settings (pydantic-settings, lee .env)
├── server.py                    # Registro central de tools + resources MCP
├── audit.py                     # @audit_tool — logging JSON-Lines a audit.log
│
├── models/
│   ├── vulnerability.py         # Finding, VerdictTaxonomy, AnalysisJustification, Evidence
│   ├── reachability.py          # ReachabilityResult, ImportUsage, ReproducibilityMetadata
│   └── security_policy.py      # SecurityPolicy — límites de acceso a filesystem
│
├── clients/
│   └── dependency_track.py     # Cliente httpx async para Dependency-Track REST API
│
├── analyzers/
│   ├── base_scanner.py         # Clase abstracta ImportScanner (contrato multi-lenguaje)
│   ├── scanner_factory.py      # detect_language() + get_scanner() factory
│   ├── js_import_scanner.py    # Scanner JS/TS: require, import, dynamic, side-effect
│   └── java_import_scanner.py  # Scanner Java: import, import static, import wildcard
│
└── tools/                      # Tools MCP — lo que el LLM puede invocar
    ├── sbom_ingestion.py        # Stage 1: list_projects, get_findings, etc.
    ├── reachability.py          # Stage 2: run_reachability_filter, etc.
    ├── stage3_context.py        # Stage 3: prepare_stage3_context
    ├── code_context.py          # Stage 3: fetch_code_snippet, find_symbol_usages, etc.
    └── decision.py              # Decision: generate_finding_verdict, generate_vex_report

scripts/
├── poc_stage1.py               # POC standalone Stage 1 (conexión DT + listing)
├── poc_stage2.py               # POC standalone Stage 2 (reachability local)
└── poc_stage3.py               # POC standalone Stage 3 (pipeline completo + LLM)

main.py                         # Entrypoint: arranca el servidor MCP
audit.log                       # Log de todas las tool calls (JSON-Lines, auto-generado)
```

---

## Modelos de datos principales

### Finding (`models/vulnerability.py`)

Representa una vulnerabilidad de Dependency-Track enriquecida con datos de análisis:

```
Finding
├── component         : Component (uuid, name, version, purl, group)
├── vulnerability     : Vulnerability (uuid, vuln_id, severity, cvss, description, aliases)
├── analysis_state    : AnalysisState (NOT_SET | NOT_AFFECTED | IN_TRIAGE | EXPLOITABLE | FALSE_POSITIVE)
├── is_suppressed     : bool
├── confidence        : float [0.0 – 1.0]
├── evidence          : list[Evidence]
└── finding_id        : str (property) → "{component_uuid}:{vuln_uuid}"
```

```
Evidence
├── file              : str (ruta relativa al archivo que contiene el import)
├── line              : int
├── statement         : str (línea exacta del import)
├── matched_pattern   : str (require | import_from | import | import_static | import_wildcard)
└── reason            : str (descripción legible de por qué matchea)
```

### VerdictTaxonomy — los 7 posibles resultados

| Valor | Significado | Acción en DT | Acción en pipeline |
|---|---|---|---|
| `UNKNOWN` | Sin analizar todavía | `NOT_SET` | Bloquear por precaución |
| `NOT_REACHABLE` | Paquete instalado pero nunca importado | `NOT_AFFECTED` | PROMOTE |
| `REACHABLE` | Importado — requiere análisis Stage 3 | `IN_TRIAGE` | En espera |
| `LIKELY_EXPLOITABLE` | Importado y llamado con posible user input | `IN_TRIAGE` | BLOCK |
| `EXPLOITABLE` | Confirmado explotable | `EXPLOITABLE` | BLOCK |
| `FALSE_POSITIVE` | La vulnerabilidad no aplica al patrón de uso | `FALSE_POSITIVE` | PROMOTE |
| `NOT_APPLICABLE` | La vuln no aplica a la configuración del proyecto | `NOT_AFFECTED` | PROMOTE |

### ReachabilityResult (`models/reachability.py`)

Output de cualquier scanner:

```
ReachabilityResult
├── package           : str (import prefix resuelto)
├── project_path      : str
├── is_reachable      : bool
├── verdict           : str (NOT_REACHABLE | REACHABLE)
├── language          : str (javascript | java)
├── files_scanned     : int
├── usages            : list[ImportUsage]
├── confidence        : float [0.0 – 1.0]
├── confidence_reason : str
├── limitations       : list[str]
├── requires_human_review : bool
├── auto_justification    : str (mensaje para DT)
└── reproducibility   : ReproducibilityMetadata | None
    ├── analyzer_name     : str
    ├── analyzer_version  : str
    ├── ruleset_version   : str
    ├── timestamp         : str (ISO 8601)
    └── input_fingerprint : str (sha256 del proyecto + paquete + archivos)
```

---

## Las 15 tools MCP

El servidor MCP expone exactamente **15 tools** organizadas en 4 grupos:

### Stage 1 — Metadata-First Filter (4 tools)

```
list_projects
  Input:  (ninguno)
  Output: [{project_uuid, name, version, findings_count, ...}]
  Costo:  0 tokens — solo llama a DT API

get_project_findings
  Input:  project_uuid: str
  Output: {project, findings: [...], total_count, actionable_count}
  Costo:  0 tokens

get_actionable_findings
  Input:  project_uuid: str
  Output: {findings: [...]} — solo los que no tienen estado final (NOT_AFFECTED/FALSE_POSITIVE)
  Costo:  0 tokens

get_vulnerability_detail
  Input:  vulnerability_uuid: str
  Output: {vuln_id, severity, cvss, description, aliases, cwes, affected_versions}
  Costo:  0 tokens
```

### Stage 2 — Reachability Analysis (4 tools)

```
analyze_package_reachability
  Input:  project_path: str, package_name: str, language: str = "auto"
  Output: {verdict, is_reachable, confidence, evidence, stage3_gate, ...}
  Costo:  0 tokens — análisis regex sobre filesystem local

build_project_import_graph
  Input:  project_path: str, language: str = "auto"
  Output: {graph: {file → [packages]}, unique_packages_imported: int, ...}
  Costo:  0 tokens

run_reachability_filter
  Input:  project_uuid: str, project_path: str, dry_run: bool = True, language: str = "auto"
  Output: {not_reachable: [...], reachable: [...], stage3_candidates: [...],
           noise_reduction_pct: float, ...}
  Costo:  0 tokens — escribe en DT solo si dry_run=False
  NOTA:   Cachea scans por PURL — si spring-core tiene 10 CVEs, escanea el código 1 vez

update_finding_analysis
  Input:  project_uuid, component_uuid, vulnerability_uuid, state, details
  Output: confirmación de escritura en DT
  Costo:  0 tokens — escritura directa a DT API
```

### Stage 3 — Context Assembly + Code Access (5 tools)

```
prepare_stage3_context                              ← herramienta central de Stage 3
  Input:  project_path, package_name, vulnerability_id, severity,
          vulnerability_description, vulnerable_functions (opcional), cvss (opcional)
  Output: {
    finding: {...},
    reachability: {verdict, confidence, files_with_imports, total_call_sites_found},
    context_bundles: [{
      file, import_line, import_statement, local_binding,
      import_context: [{line_no, code}],
      vulnerable_function_calls: [{
        function, line, statement, context,
        analysis_hints: {near_user_input, sanitization_present}
      }]
    }],
    pre_analysis_signals: {
      any_call_site_near_user_input: bool,
      any_sanitization_detected: bool,
      known_vulnerable_functions_found: bool,
      risk_signal: HIGH | MEDIUM | LOW
    },
    analysis_instructions: {
      objective: str,
      check_for: [lista de preguntas específicas para el LLM],
      verdict_options: [...],
      justification_options: [...]
    }
  }
  Costo:  0 tokens — determinístico, pre-computa todo el contexto

fetch_code_snippet
  Input:  project_path, file (relativo), start_line, end_line
  Output: {snippet: [líneas], truncated: bool, total_lines: int}
  Límite: max 50 líneas por llamada (SecurityPolicy)

get_function_context
  Input:  project_path, file, function_name
  Output: {matches: [{definition_line, context_start, context_end, snippet}]}
  Detecta:  JS (function/arrow/method) y Java (modificadores + tipo de retorno + nombre)

get_call_context
  Input:  project_path, file, function_name
  Output: {call_sites: [{line, statement, context}], call_site_count: int}
  Límite: máx 20 call sites por llamada

find_symbol_usages
  Input:  project_path, symbol_name, file_extension (opcional)
  Output: {usages: [{file, line, statement}], usage_count: int, capped: bool}
  Límite: máx 100 resultados — usa word boundary regex
```

### Decision Engine (2 tools)

```
generate_finding_verdict
  Input:  finding_id, verdict, justification, confidence, evidence, analysis_details
  Output: {
    finding_id, verdict, justification, confidence,
    dt_analysis_state,  ← lo que se escribe en DT
    stage3_gate: {stage3_allowed, reason},
    timestamp
  }
  Costo:  0 tokens — validación + estructuración del veredicto

generate_vex_report
  Input:  project_name, project_version, findings: [...]
  Output: {
    @context: "https://openvex.dev/ns/v0.2.0",
    pipeline_decision: BLOCK | PROMOTE,   ← la decisión final del pipeline
    summary: {total, affected, not_affected, under_investigation},
    statements: [{vulnerability, products, status, justification, confidence}]
  }
  Costo:  0 tokens — genera el documento OpenVEX
```

---

## Los 4 recursos MCP

Los recursos son datos de solo lectura que el LLM puede consultar para contexto:

```
taxonomy://verdicts
  → Lista canónica de VerdictTaxonomy + AnalysisJustification con descripciones
  → Útil para que el LLM sepa qué valores son válidos antes de llamar generate_finding_verdict

policy://analysis-rules
  → SecurityPolicy activa (max_file_size, max_snippet_lines, disallowed_paths)
  → stage3_confidence_threshold
  → Reglas de uso LLM (qué está prohibido hacer con las tools)

project://{project_id}/findings
  → Findings actionables de un proyecto directamente desde DT
  → Equivale a llamar get_actionable_findings pero como recurso consultable

project://{project_id}/reachability-summary
  → Metadatos del schema de run_reachability_filter
  → Nota: para datos reales hay que llamar el tool (el recurso es solo el esquema)
```

---

## Cómo funciona el análisis de reachability

### Detección de lenguaje (`scanner_factory.py`)

Prioridad de detección:

```
1. PURL scheme (más confiable)
   pkg:maven/ → java
   pkg:npm/   → javascript
   pkg:pypi/  → python (sin scanner implementado aún)

2. Maven GAV heuristic
   Si el nombre contiene ":" y el groupId empieza por "org.", "com.", "net.", etc. → java

3. Marcadores en raíz del proyecto
   pom.xml / build.gradle / build.gradle.kts → java
   package.json                              → javascript
   go.mod                                    → go (sin scanner)
   Cargo.toml                                → rust (sin scanner)

4. Default → javascript
```

### Scanner JavaScript (`js_import_scanner.py`)

Detecta 4 patrones de import en archivos `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`:

```javascript
const adm = require('adm-zip')              // require
import AdmZip from 'adm-zip'               // import_from
import('adm-zip').then(...)                // import_dynamic
import 'adm-zip'                           // import_side_effect (side effects only)
```

Ignora: `node_modules/`, `dist/`, `build/`, `.git/`, archivos > 1MB, symlinks.

**Confianza heurística:**
```
is_reachable = True        → 1.00
files_scanned ≥ 100        → 0.95
files_scanned ≥ 50         → 0.90
files_scanned ≥ 20         → 0.80
files_scanned ≥ 5          → 0.70   ← umbral Stage 3
files_scanned < 5          → 0.50
files_scanned = 0          → 0.00
```

### Scanner Java (`java_import_scanner.py`)

Detecta 3 patrones en archivos `.java`:

```java
import org.springframework.web.bind.annotation.RestController;   // import
import static org.springframework.util.Assert.notNull;          // import_static
import org.apache.commons.collections.*;                         // import_wildcard
```

**Resolución Maven → prefijo Java:**
- PURL `pkg:maven/org.springframework/spring-core@5.3.0` → extrae groupId `org.springframework` → busca `import org.springframework.*`
- Para artefactos legacy (donde groupId ≠ paquete Java), existe una tabla de 30+ mappings:

```
commons-collections → org.apache.commons.collections
guava               → com.google.common
gson                → com.google.gson
log4j-core          → org.apache.logging.log4j
httpclient          → org.apache.http
bcprov-jdk15on      → org.bouncycastle
... (30+ entradas)
```

Ignora: `target/`, `build/`, `.gradle/`, `.idea/`, `generated-sources/`.

---

## Stage 3 — Señales pre-análisis

Antes de que el LLM vea el código, `prepare_stage3_context` anota cada call site con señales automáticas:

### Señal: `near_user_input`

**JavaScript/Node.js:**
```
req.body / req.query / req.params / req.headers / req.files / req.cookies
request.body / request.data / request.form / request.json
ctx.request / ctx.query / ctx.body
process.argv / readline / stdin
event.data / socket.data
```

**Java/Spring Boot:**
```
@RequestParam / @RequestBody / @PathVariable / @RequestHeader
@ModelAttribute / @RequestPart / MultipartFile
request.getParameter / request.getInputStream / getQueryString
HttpServletRequest / System.in
```

### Señal: `sanitization_present`

**JavaScript:**
```
sanitize / escape / validate / whitelist / allowlist
.replace( / .slice( / path.basename / isValid / isSafe / checkPath / normalize
```

**Java:**
```
@Valid / @Validated / BindingResult / Errors / Validator
StringEscapeUtils / HtmlUtils / ESAPI / AntiSamy
@Pattern / @NotNull / @NotBlank / @Size / @Min / @Max / @Email
javax.validation / jakarta.validation
Paths.get / Path.normalize / FilenameUtils.getName
```

### Risk signal resultante

```
near_user_input = true  AND  sanitization_present = false  →  HIGH
near_user_input = true  AND  sanitization_present = true   →  MEDIUM
near_user_input = false                                    →  LOW
```

---

## Flujo completo de datos (Stage 1 → 2 → 3 → Decision)

```
DT API
  │
  ├─ get_actionable_findings(project_uuid)
  │    └─ 267 findings [{component + CVE + severity + purl}]
  │
  ▼
Stage 2: run_reachability_filter(project_uuid, project_path)
  │
  ├─ Para cada finding:
  │    ├─ _resolve_package_identifier()  →  PURL > Maven GAV > nombre plain
  │    ├─ scanner.scan_project()         →  regex sobre .java / .js files
  │    └─ _stage3_gate()                 →  ¿puede ir a Stage 3?
  │
  ├─ NOT_REACHABLE (80-90% típicamente)
  │    └─ dt_client.update_analysis(state=NOT_AFFECTED)  [si dry_run=False]
  │
  └─ REACHABLE + stage3_allowed=True  →  stage3_candidates list
          │
          ▼
Stage 3: prepare_stage3_context(project_path, package, vuln_id, vulnerable_functions)
  │
  ├─ Re-scan del proyecto para obtener import locations
  ├─ _build_context_bundle() para cada archivo con import
  │    ├─ Import context (±3 líneas alrededor del import)
  │    ├─ _find_call_sites() para cada función vulnerable
  │    └─ Anotación: near_user_input, sanitization_present
  └─ Emite: context_bundles + pre_analysis_signals + analysis_instructions
          │
          ▼
LLM (Claude API — ÚNICO punto de consumo de tokens)
  │
  ├─ Recibe el context bundle completo
  ├─ Analiza: ¿es explotable en este contexto específico?
  └─ Responde JSON: {verdict, justification, confidence, analysis}
          │
          ▼
Decision:
  ├─ generate_finding_verdict()   →  registro canónico del veredicto
  ├─ update_finding_analysis()    →  escribe en DT (si --apply)
  └─ generate_vex_report()        →  documento OpenVEX {pipeline_decision: BLOCK|PROMOTE}
```

---

## Seguridad interna — SecurityPolicy

Todos los scanners y tools de código están gobernados por `DEFAULT_POLICY`:

```python
class SecurityPolicy:
    disallowed_paths: list[str]     # node_modules, .git, dist, build, ...
    max_file_size_bytes: int        # 1 MB (1_048_576)
    max_scan_depth: int             # 20 niveles de directorio
    follow_symlinks: bool           # False — nunca seguir symlinks
    max_snippet_lines: int          # 50 líneas máx por snippet al LLM
```

Adicionalmente, todas las tools que acceden al filesystem tienen un **path traversal guard**:

```python
def _safe_resolve(project_path, relative_file) -> Path:
    root = Path(project_path).resolve()
    target = (root / relative_file).resolve()
    if not str(target).startswith(str(root)):
        raise ValueError("Path traversal detected")
    return target
```

---

## Observabilidad — audit.log

Cada tool call decorada con `@audit_tool` escribe una línea JSON en `audit.log`:

```json
{
  "tool": "run_reachability_filter",
  "timestamp": "2025-04-22T10:31:05.123Z",
  "input": {"project_uuid": "ad5f9c55", "project_path": "/path/to/app", "dry_run": true},
  "duration_ms": 847,
  "output_hash": "a3f2b1c9",
  "side_effects": "none"
}
```

Esto permite auditar cuándo y con qué parámetros se tomaron decisiones de seguridad, requisito en entornos regulados.

---

## Integración actual: MCP + Dependency-Track

```
┌─────────────────────┐         ┌─────────────────────────────┐
│   Claude Desktop /  │  MCP    │        ZeroNoise            │
│   Claude VSCode     │◄───────►│     (FastMCP server)        │
│   Extension         │  stdio  │                             │
└─────────────────────┘         │  15 tools + 4 resources     │
                                 │                             │
                                 │  ┌──────────────────────┐  │
                                 │  │  Dependency-Track    │  │
                                 │  │  http://localhost:8080│  │
                                 │  └──────────────────────┘  │
                                 │                             │
                                 │  ┌──────────────────────┐  │
                                 │  │   Código fuente      │  │
                                 │  │   del proyecto       │  │
                                 │  │   (filesystem local) │  │
                                 │  └──────────────────────┘  │
                                 └─────────────────────────────┘
```

### Cómo arrancar el servidor

```bash
# 1. Configurar .env
cp .env.example .env
# Editar: DT_API_KEY, ANTHROPIC_API_KEY

# 2. Instalar dependencias
uv sync

# 3. Arrancar servidor MCP
uv run python main.py
```

### Agregar al mcp.json de VSCode / Claude Desktop

```json
{
  "mcpServers": {
    "zeronoise": {
      "command": "uv",
      "args": ["run", "python", "main.py"],
      "cwd": "/ruta/al/proyecto/ZeroNoise"
    }
  }
}
```

### POC scripts (sin UI, ejecución directa)

```bash
# Stage 1 — Listar y filtrar findings de DT
uv run python scripts/poc_stage1.py --project-uuid ad5f9c55-...

# Stage 2 — Analizar reachability contra código fuente
uv run python scripts/poc_stage2.py --project-uuid ad5f9c55-... --project-path /ruta/fuente
uv run python scripts/poc_stage2.py --project-path /ruta --package adm-zip  # paquete específico

# Stage 3 — Pipeline completo con LLM
uv run python scripts/poc_stage3.py --project-uuid ad5f9c55-... --project-path /ruta --analyze
uv run python scripts/poc_stage3.py --project-uuid ... --project-path ... --analyze --apply
```

---

## Integración en CI/CD (objetivo principal)

El caso de uso ideal es que ZeroNoise actúe como **security gate** en el pipeline:

```
┌────────────────────────────────────────────────────────────┐
│                     CI/CD Pipeline                          │
│                                                             │
│  build → test → scan_sca ──► ZeroNoise ──► deploy_decision │
│                                   │                         │
│                            ┌──────▼──────┐                 │
│                            │  VEX Report │                 │
│                            │  BLOCK/     │                 │
│                            │  PROMOTE    │                 │
│                            └─────────────┘                 │
└────────────────────────────────────────────────────────────┘
```

**Trigger sugerido (GitHub Actions):**
```yaml
- name: ZeroNoise security gate
  run: |
    uv run python scripts/poc_stage3.py \
      --project-uuid ${{ vars.DT_PROJECT_UUID }} \
      --project-path ${{ github.workspace }} \
      --analyze --apply
    # El script retorna exit code 1 si pipeline_decision == BLOCK
```

---

## Integraciones posibles a futuro

### Git / SCM
- **Webhook en merge request:** ejecutar el pipeline cuando se actualiza `pom.xml` / `package.json`
- **Diff-aware scanning:** solo re-analizar paquetes cuya versión cambió respecto al commit anterior
- **GitHub/GitLab Security Advisories API:** enriquecer findings con datos de vulnerable_functions directamente de advisories

### Plataformas SCA alternativas
- **Snyk API** — reemplazar o complementar a Dependency-Track como fuente de findings
- **OWASP Dependency-Check** — ingerir su reporte XML como alternativa offline
- **Grype / Syft** — SBOM generation + vulnerability matching sin servidor externo

### Scanners estáticos avanzados
- **Semgrep** — análisis de data flow para Stage 2+ (reemplaza regex con AST)
- **CodeQL** — call graph real para determinar reachability sin heurística regex
- Ambos eliminarían los falsos negativos de reflection y auto-configuration

### Notificaciones y dashboards
- **Slack / Teams** — notificar al equipo de seguridad cuando `EXPLOITABLE` se detecta
- **Jira / Linear** — crear ticket automático con el contexto del LLM
- **Grafana** — métricas de noise reduction % por proyecto/sprint

### Transport SSE
El servidor ya tiene soporte para `MCP_TRANSPORT=sse` en `config.py`. Con SSE se puede:
- Tener múltiples clientes simultáneos (un servidor, N usuarios)
- Integrarlo en una webapp interna de seguridad
- Exponer las tools vía HTTP para pipelines que no soportan stdio

---

## Lenguajes soportados y roadmap

| Lenguaje | Import Scanner | Stage 3 Patterns | Estado |
|---|---|---|---|
| JavaScript / TypeScript | ✅ js_import_scanner | ✅ Express/Node patterns | Completo |
| Java (Spring/Maven/Gradle) | ✅ java_import_scanner | ✅ Spring Boot patterns | Completo |
| Kotlin (.kt) | ⚠️ Parcial (usa JS scanner) | ⚠️ Sin patterns específicos | Fix trivial: agregar .kt a _SOURCE_EXTENSIONS |
| Python | ❌ Sin scanner | ❌ | Pendiente |
| Go | ❌ Sin scanner | ❌ | Pendiente |
| Rust | ❌ Sin scanner | ❌ | Pendiente |
| Jakarta EE / Quarkus | ✅ (mismo scanner Java) | ⚠️ Sin @PathParam/@QueryParam | Pendiente patterns |

### Añadir un nuevo lenguaje (Python como ejemplo)

La arquitectura está preparada. Solo requiere:

1. Crear `analyzers/py_import_scanner.py` que extienda `ImportScanner`
2. Implementar `scan_project()` detectando `import library` y `from library import`
3. Agregar `"python"` a `get_scanner()` en `scanner_factory.py`
4. Agregar patrones de user input Django/Flask en `stage3_context.py`

No se toca ninguna otra capa del sistema.

---

## Limitaciones conocidas y técnicas

| Limitación | Impacto | Workaround actual |
|---|---|---|
| Reflection / `Class.forName` no detectada | Falso negativo en deserialization gadgets | Documentado en `_LIMITATIONS`, requiere human review |
| Spring auto-configuration sin imports explícitos | Falso negativo para librerías autoconfigured | Stage 3 puede usarse manualmente con `--package` |
| Regex vs AST — falsos positivos en strings/comentarios | Bajo impacto en práctica | `get_call_context` documenta limitación |
| Confidencia heurística, no formal | NOT_REACHABLE < 0.70 requiere revisión humana | `requires_human_review` flag en resultado |
| Ártefactos legacy sin mapping (javassist, cglib, woodstox) | Falso negativo para esas librerías | Agregar a `_LEGACY_IMPORT_MAPPINGS` |
| Kotlin (.kt) no escaneado | Spring Boot 3.x subestimado | Agregar `.kt` a `_SOURCE_EXTENSIONS` |

---

## Glosario técnico

| Término | Definición |
|---|---|
| **MCP (Model Context Protocol)** | Protocolo de Anthropic para que LLMs invoquen tools externas de forma estructurada |
| **SBOM** | Software Bill of Materials — lista de todas las dependencias de un proyecto |
| **SCA** | Software Composition Analysis — análisis de vulnerabilidades en dependencias |
| **PURL** | Package URL — identificador estándar: `pkg:maven/org.springframework/spring-core@5.3.0` |
| **Maven GAV** | GroupId:ArtifactId:Version — coordenadas de un paquete Maven |
| **VEX** | Vulnerability Exploitability eXchange — documento que justifica por qué una vuln no es explotable |
| **OpenVEX** | Implementación open source del estándar VEX |
| **Reachability** | Si existe un camino de ejecución real desde el código de la aplicación hasta la función vulnerable |
| **Stage 3 Gate** | Condición triple: verdict=REACHABLE + evidence≠∅ + confidence≥0.70 |
| **Noise reduction %** | Porcentaje de findings eliminados automáticamente (NOT_REACHABLE / total_actionable) |
| **Heuristic confidence** | Confianza calculada por tamaño del proyecto escaneado, no por análisis formal |
| **Dry run** | Modo de ejecución que analiza pero no escribe en Dependency-Track |
