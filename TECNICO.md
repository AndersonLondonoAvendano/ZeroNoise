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

Esto se traduce en cuatro principios de implementación:

1. **Cero tokens en Stage 0, 1 y 2.** Todo el análisis de versiones, metadatos e importaciones es determinístico.
2. **Evidencia antes de tokens.** Stage 3 (LLM) solo se ejecuta si existe evidencia de reachability con confianza ≥ 0.70.
3. **Acceso quirúrgico al código.** El LLM nunca recibe archivos completos — solo snippets acotados por `SecurityPolicy.max_snippet_lines` (50 líneas).
4. **Dos frentes operacionales.** Dependency-Track (post-SBOM) y OWASP Dep-Check (fast-gate de CI/CD) son ciudadanos de primera clase.

---

## Arquitectura general

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            PIPELINE ZERONOISE                                │
│                                                                              │
│  ┌────────────┐   ┌──────────────────┐   ┌──────────────────┐               │
│  │  STAGE 0   │   │    STAGE 2       │   │     STAGE 3      │               │
│  │  Artifact  │──▶│  Reachability    │──▶│  Contextual      │               │
│  │  Version   │   │   Analysis       │   │  Analysis (LLM)  │               │
│  └────────────┘   └──────────────────┘   └──────────────────┘               │
│       │                  │                        │                          │
│  0 tokens LLM       0 tokens LLM          Tokens LLM aquí                   │
│  JAR + dep-tree     Regex estático        (solo para REACHABLE)              │
│                                                   │                          │
│                                          ┌────────▼──────────┐              │
│                                          │  DECISION ENGINE  │              │
│                                          │  Verdict + VEX    │              │
│                                          └───────────────────┘              │
│                                                                              │
│  ┌──────────────────────────┐   ┌──────────────────────────────────┐        │
│  │  FRENTE 1: DT API        │   │  FRENTE 2: OWASP DEP-CHECK       │        │
│  │  analyze_project_vulns   │   │  analyze_depcheck_report         │        │
│  │  Stage 1 → 0 → 2 → 3    │   │  dep-check.json → 0 → 2 → 3     │        │
│  └──────────────────────────┘   └──────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Estructura de archivos

```
zeronoise/
├── config.py                    # Settings (pydantic-settings, lee .env)
├── server.py                    # Registro central — 17 tools + 4 resources MCP
├── audit.py                     # @audit_tool + @safe_tool — logging JSON-Lines a audit.log
│
├── models/
│   ├── vulnerability.py         # Finding, VerdictTaxonomy, AnalysisJustification, Evidence
│   ├── reachability.py          # ReachabilityResult, ImportUsage, ReproducibilityMetadata
│   ├── security_policy.py       # SecurityPolicy, DEFAULT_POLICY
│   ├── artifact_finding.py      # Stage 0: VersionVerdict, ArtifactVersion, VersionVerification
│   └── depcheck_finding.py      # PurlConfidence, CvssSource, DepCheckCvss, AffectedPackage, DepCheckFinding
│
├── clients/
│   ├── dependency_track.py      # Cliente httpx async para Dependency-Track REST API
│   └── depcheck_ingester.py     # DepCheckIngester — parsea y normaliza reportes JSON de OWASP Dep-Check
│
├── analyzers/
│   ├── base_scanner.py          # Clase abstracta ImportScanner (contrato multi-lenguaje)
│   ├── scanner_factory.py       # detect_language() + get_scanner() factory
│   ├── js_import_scanner.py     # Scanner JS/TS: require, import, dynamic, side-effect
│   ├── java_import_scanner.py   # Scanner Java/Kotlin: import, import static, wildcard (.java, .kt)
│   ├── artifact_inspector.py    # Stage 0: ArtifactInspector — BuildTool detection + fat JAR inspection
│   ├── dependency_tree_parser.py # Stage 0: DependencyTreeParser — Maven/Gradle dep tree + starter resolution
│   └── project_context_reader.py # ProjectContextReader — README, build config, YAML para Stage 3
│
└── tools/
    ├── sbom_ingestion.py        # Stage 1: list_projects, get_findings, etc.
    ├── reachability.py          # Stage 2: run_reachability_filter, etc.
    ├── stage3_context.py        # Stage 3: prepare_stage3_context
    ├── code_context.py          # Stage 3: fetch_code_snippet, find_symbol_usages, etc.
    ├── decision.py              # Decision: generate_finding_verdict, generate_vex_report
    ├── depcheck_gate.py         # Fast-gate: analyze_depcheck_report
    ├── dt_background.py         # DT pipeline: analyze_project_vulnerabilities
    └── _validators.py           # Validación compartida: UUID, paths, CVE IDs, rangos de líneas

scripts/
├── poc_stage1.py                # POC standalone Stage 1 (conexión DT + listing)
├── poc_stage2.py                # POC standalone Stage 2 (reachability local)
├── poc_stage3.py                # POC standalone Stage 3 (pipeline completo + LLM)
├── poc_depcheck.py              # POC fast-gate: analyze_depcheck_report
└── poc_artifact_verify.py       # POC Stage 0: artifact inspector + dep tree parser

main.py                          # Entrypoint: arranca el servidor MCP
audit.log                        # Log de todas las tool calls (JSON-Lines, auto-generado)
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

### DepCheckFinding (`models/depcheck_finding.py`)

Representa una vulnerabilidad del reporte JSON de OWASP Dep-Check. **Paralelo a `Finding` — sin UUIDs.**

```
DepCheckFinding
├── cve_id            : str
├── severity          : str
├── cvss              : DepCheckCvss
│   ├── score             : float
│   ├── source            : CvssSource (V3 | V2_FALLBACK | UNAVAILABLE)
│   ├── attack_vector     : str
│   └── ... (demás métricas CVSS)
├── description       : str
├── cwes              : list[str]
├── affected_packages : list[AffectedPackage]
│   ├── file_name         : str
│   ├── purl              : str | None
│   ├── purl_confidence   : PurlConfidence (HIGH | MEDIUM | LOW | UNAVAILABLE)
│   ├── artifact_name     : str
│   ├── artifact_version  : str
│   ├── cpe_version_mismatch : bool
│   └── shadowed_dependency  : str | None
├── requires_human_review : bool
└── primary_package   : AffectedPackage | None (property — selecciona por confianza de PURL)

Properties:
  effective_purl         → PURL del primary_package
  can_run_reachability   → True si primary_package tiene artifact_name
  exceeds_cvss_threshold → True si score >= threshold
  finding_id             → f"{cve_id}:{primary_package.artifact_name}"
```

### VersionVerification (`models/artifact_finding.py`)

```
VersionVerification
├── package_name          : str
├── reported_version      : str  ← lo que reportó dep-check
├── real_version          : str | None  ← lo que está en el JAR o árbol
├── verdict               : VersionVerdict
├── found_in_artifact     : ArtifactVersion | None
│   ├── artifact_name        : str
│   ├── resolved_version     : str
│   ├── source               : "pom_properties" | "jar_filename"
│   └── jar_path             : str (ruta dentro del fat JAR)
├── found_in_tree         : str | None  (línea del dep tree)
├── is_starter_wrapper    : bool
├── actual_library_name   : str | None
├── version_is_vulnerable : bool | None
└── analysis_note         : str

Properties:
  requires_reanalysis → True si verdict == MISMATCH o NOT_FOUND
  summary             → string legible para logging/audit
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
```

---

## Las 17 tools MCP

El servidor MCP expone **17 tools** organizadas en 6 grupos:

### Stage 1 — Metadata-First Filter (4 tools)

```
list_projects
  Input:  (ninguno)
  Output: [{project_uuid, name, version, findings_count, ...}]
  Costo:  0 tokens — solo llama a DT API

get_project_findings
  Input:  project_uuid: str, offset: int = 0
  Output: {project, findings: [...], total_count, actionable_count, has_more, next_offset}
  Costo:  0 tokens

get_actionable_findings
  Input:  project_uuid: str, offset: int = 0
  Output: {findings: [...], has_more, next_offset} — solo los sin estado final
  Costo:  0 tokens

get_vulnerability_detail
  Input:  source: str, vuln_id: str
  Output: {vuln_id, severity, cvss, description, aliases, cwes, affected_versions}
  Costo:  0 tokens
```

### Stage 2 — Reachability Analysis (4 tools)

```
analyze_package_reachability
  Input:  project_path: str, package_name: str, language: str = "auto"
  Output: {verdict, is_reachable, confidence, evidence, stage3_gate, ...}
  Costo:  0 tokens

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
  Costo:  0 tokens

fetch_code_snippet
  Input:  project_path, file (relativo), start_line, end_line
  Output: {snippet: [líneas], truncated: bool, total_lines: int}
  Límite: max 50 líneas por llamada (SecurityPolicy)

get_function_context
  Input:  project_path, file, function_name
  Output: {matches: [{definition_line, context_start, context_end, snippet}]}

get_call_context
  Input:  project_path, file, function_name
  Output: {call_sites: [{line, statement, context}], call_site_count: int}
  Límite: máx 20 call sites por llamada

find_symbol_usages
  Input:  project_path, symbol_name, file_extension (opcional)
  Output: {usages: [{file, line, statement}], usage_count: int, capped: bool}
  Límite: máx 100 resultados
```

### Decision Engine (2 tools)

```
generate_finding_verdict
  Input:  finding_id, verdict, justification, confidence, evidence, analysis_details
  Output: {
    finding_id, verdict, justification, confidence,
    dt_analysis_state,
    stage3_gate: {stage3_allowed, reason},
    timestamp
  }

generate_vex_report
  Input:  project_name, project_version, findings: [...]
  Output: {
    @context: "https://openvex.dev/ns/v0.2.0",
    pipeline_decision: BLOCK | PROMOTE,
    summary: {total, affected, not_affected, under_investigation},
    statements: [...],
    integrity: {algorithm, hash, timestamp}  ← SHA-256 anti-tampering
  }
```

### Fast-Gate Tools (2 tools orquestadoras)

```
analyze_depcheck_report
  Input:  report_path: str, project_path: str, cvss_threshold: float = None, dry_run: bool = True
  Output: {
    pipeline_decision: BLOCK | PROMOTE,
    summary: {total_cves, analyzed, false_positives, not_reachable, reachable, exploitable},
    verdicts: [{cve_id, package, verdict, justification, real_version, ...}],
    vex_report: {...},
    block_reason: str | None
  }
  Flujo: DepCheckIngester → filtro CVSS → Stage 0 (JAR + tree) → Stage 2 → Stage 3 heurístico
  Costo: 0 tokens LLM (Stage 3 heurístico sin LLM)

analyze_project_vulnerabilities
  Input:  project_uuid: str, project_path: str, severity_filter: str = "HIGH", dry_run: bool = True
  Output: (mismo esquema que analyze_depcheck_report)
  Flujo:  Stage 1 (DT API) → filtro severidad → Stage 0 → Stage 2 → Stage 3
          + ProjectContextReader enriquece Stage 3
  Costo:  0 tokens LLM por defecto (heurístico); tokens si se combina con Stage 3 LLM manual
```

---

## Los 4 recursos MCP

```
taxonomy://verdicts
  → Lista canónica de VerdictTaxonomy + AnalysisJustification con descripciones
  → stage3_eligible_verdicts: ["REACHABLE", "UNKNOWN"]

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

## Stage 0 — Verificación de versión (en detalle)

### ArtifactInspector (`analyzers/artifact_inspector.py`)

Abre el fat JAR compilado del proyecto y verifica qué versión de cada librería está **realmente empaquetada**.

**Problema que resuelve:** Un scanner puede reportar `thymeleaf@3.4.6` como vulnerable, pero el fat JAR puede contener `thymeleaf@3.4.5` (fuera del rango afectado).

**Búsqueda del artefacto:**

```python
_SEARCH_PATHS_BY_TOOL = {
    "maven":   ["target", "build/libs", "build/outputs", "out/artifacts"],
    "gradle":  ["build/libs", "build/outputs", "out/artifacts", "target"],
    "unknown": ["target", "build/libs", "build/outputs", "out/artifacts"],
}
```

`find_artifact()` detiene la búsqueda en cuanto encuentra candidatos — evita mezclar artefactos de rutas distintas. Excluye `*-plain.jar`, `*-sources.jar`, `*-javadoc.jar`.

**Construcción del índice (`build_jar_index()`):**
1. Abre el ZIP y recorre entradas en `BOOT-INF/lib/`, `WEB-INF/lib/`, `lib/`
2. Para cada JAR anidado: intenta leer `pom.properties` (fuente: `pom_properties`); si no, extrae del nombre de fichero con regex (fuente: `jar_filename`)
3. Normaliza qualifiers antes de comparar: `.Final`, `.RELEASE`, `.GA`, `.SP\d+`

### DependencyTreeParser (`analyzers/dependency_tree_parser.py`)

Obtiene la versión **efectivamente resuelta** en el classpath runtime del proyecto.

**Fuentes de datos (prioridad decreciente):**
1. `dep-tree.txt` o `dependency-tree.txt` pre-generado en la raíz
2. `mvn dependency:tree -DoutputType=text -Dscope=runtime -q` (Maven)
3. `gradlew dependencies --configuration runtimeClasspath -q` (Gradle; usa `cmd /c gradlew.bat` en Windows)
4. `UNVERIFIABLE` si ninguna fuente disponible

**Formatos soportados:**

Maven:
```
[INFO] |  +- io.netty:netty-resolver-dns:jar:4.1.128.Final:compile
```

Gradle (con version redirect):
```
+--- io.netty:netty-resolver-dns:4.1.128.Final -> 4.1.132.Final (*)
```

**Tabla starter → librería real (selección):**

| Starter declarado | Librería real evaluada |
|---|---|
| `spring-boot-starter-thymeleaf` | `thymeleaf` |
| `spring-boot-starter-web` | `spring-webmvc` |
| `spring-boot-starter-data-jpa` | `hibernate-core` |
| `spring-boot-starter-security` | `spring-security-core` |
| `spring-boot-starter-webflux` | `reactor-netty` |
| `spring-cloud-starter-openfeign` | `feign-core` |
| `thymeleaf-spring6` | `thymeleaf` |
| (50+ entradas más) | |

**`resolve_effective_version()` — resolución avanzada:**
- Si el artifact no está directamente en el árbol, busca sub-módulos relacionados
- Estrategia genérica: extrae keywords del nombre, busca en el árbol por coincidencia de palabras (`netty-resolver-dns` → busca todos `netty-*`)
- Si hay versiones mixtas, retorna la más alta

### ProjectContextReader (`analyzers/project_context_reader.py`)

Lee archivos de configuración del proyecto para enriquecer el contexto de Stage 3.

**Archivos leídos:**
- `README.md` (o `README.rst`) — descripción y propósito del proyecto
- `build.gradle` / `pom.xml` — Spring Boot version, Java version, BOMs declarados, módulos excluidos
- `src/main/resources/application.yml` (o `.properties`) — configuración de la aplicación
- `docker-compose.yml` (o `.yaml`) — infraestructura del entorno

**Output (`ProjectContext`):**
- `spring_boot_version` — versión detectada del framework
- `java_version` — versión de Java del proyecto
- `declared_boms` — lista de BOMs (relevante para versiones gestionadas)
- `excluded_modules` — módulos Maven/Gradle excluidos (pueden eliminar dependencias transitivas)
- `package_manager` — "maven" | "gradle" | "unknown"
- `to_llm_context()` — genera string formateado para el LLM (max ~6000 chars total)

---

## DepCheckIngester (`clients/depcheck_ingester.py`)

Parsea y normaliza el reporte JSON de OWASP Dependency-Check. Maneja 6 casos de normalización:

| Caso | Descripción |
|---|---|
| CASO 1 | PURL presente y explícito — HIGH confidence |
| CASO 2 | PURL ausente, artifact reconocido — reconstruye PURL (MEDIUM confidence) |
| CASO 3 | Fat JAR shadeado (ej: `grpc-netty-shaded`) — mapeo conocido |
| CASO 4 | CVSS v3 ausente — fallback a CVSS v2 con flag `requires_human_review` |
| CASO 5 | Mismo CVE en múltiples JARs — deduplica, guarda todos como `affected_packages` |
| CASO 6 | Sin CVSS alguno — `score=0.0`, `source=UNAVAILABLE` |

**Tabla de mappings Maven (50+ entradas)** para reconstruir PURL cuando el reporte no lo incluye. Mapea `artifact-name` → `(groupId, artifactId)`.

**CLI standalone:**
```bash
python -m zeronoise.clients.depcheck_ingester report.json 7.0
```
Imprime diagnóstico detallado de cada CVE con confianza de PURL, CVSS source, mismatches.

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

Detecta 4 patrones en archivos `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`:

```javascript
const adm = require('adm-zip')              // require
import AdmZip from 'adm-zip'               // import_from
import('adm-zip').then(...)                // import_dynamic
import 'adm-zip'                           // import_side_effect
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

Detecta 3 patrones en archivos `.java` y `.kt`:

```java
import org.springframework.web.bind.annotation.RestController;   // import
import static org.springframework.util.Assert.notNull;          // import_static
import org.apache.commons.collections.*;                         // import_wildcard
```

**Resolución Maven → prefijo Java:**
- PURL `pkg:maven/org.springframework/spring-core@5.3.0` → extrae groupId `org.springframework` → busca `import org.springframework.*`
- Para artefactos legacy (donde groupId ≠ paquete Java), tabla de 30+ mappings:

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

Antes de que el LLM vea el código, `prepare_stage3_context` anota cada call site:

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

## Flujo completo de datos

### Frente 1: analyze_project_vulnerabilities (DT)

```
DT API
  │
  ├─ get_actionable_findings(project_uuid)
  │    └─ N findings filtrados por severity_filter
  │
  ▼
Stage 0: ArtifactInspector + DependencyTreeParser
  │
  ├─ verify_version(artifact_name, reported_version)  ×2
  │    ├─ MISMATCH → ajusta versión para evaluación
  │    ├─ NOT_FOUND → FALSE_POSITIVE (no está en runtime)
  │    └─ CONFIRMED / UNVERIFIABLE → continúa
  │
  ▼
Stage 2: run_reachability_filter(project_uuid, project_path)
  │
  ├─ Para cada finding:
  │    ├─ _resolve_package_identifier()  →  PURL > Maven GAV > nombre plain
  │    ├─ scanner.scan_project()         →  regex sobre .java / .js files
  │    └─ _stage3_gate()                 →  ¿puede ir a Stage 3?
  │
  ├─ NOT_REACHABLE → NOT_AFFECTED [si dry_run=False, escribe en DT]
  │
  └─ REACHABLE + stage3_allowed → stage3_candidates
          │
          ▼
Stage 3: prepare_stage3_context + heurísticas + LLM (si se invoca manualmente)
  │
  ├─ Pre-análisis de señales (near_user_input, sanitization)
  ├─ ProjectContextReader enriquece con README + build + YAML
  └─ risk_signal → LIKELY_EXPLOITABLE | REACHABLE
          │
          ▼
Decision:
  ├─ generate_finding_verdict()
  ├─ update_finding_analysis() [si dry_run=False]
  └─ generate_vex_report() → {pipeline_decision: BLOCK|PROMOTE}
```

### Frente 2: analyze_depcheck_report (OWASP Dep-Check)

```
dep-check.json
  │
  ├─ DepCheckIngester.load() → list[DepCheckFinding]
  ├─ filter_by_cvss(threshold) → solo CVSS >= gate_cvss_threshold
  │
  ▼
Stage 0 (por cada finding):
  │
  ├─ DependencyTreeParser.verify_version() → versión en árbol
  ├─ ArtifactInspector.verify_version() → versión en JAR
  └─ _check_version_against_advisory() → ¿la versión real está en el rango vulnerable?
       ├─ NO → FALSE_POSITIVE (versión fuera de rango)
       └─ YES → continúa a Stage 2
          │
          ▼
Stage 2:
  │
  ├─ scanner.scan_project(project_path, package_name)
  ├─ NOT_REACHABLE → NOT_AFFECTED (no importado)
  └─ REACHABLE → Stage 3 heurístico
          │
          ▼
Stage 3 heurístico (0 tokens LLM):
  │
  ├─ _find_call_sites() → ¿se llama la función vulnerable?
  ├─ near_user_input → HIGH risk
  └─ risk_signal → LIKELY_EXPLOITABLE | REACHABLE | FALSE_POSITIVE
          │
          ▼
Output: pipeline_decision (BLOCK si any(verdict ∈ {EXPLOITABLE, LIKELY_EXPLOITABLE}))
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

Path traversal guard en `_safe_resolve()`:

```python
def _safe_resolve(project_path: str, relative_file: str) -> Path:
    _validate_file_path(relative_file)   # rechaza '..', '~', null bytes, shell chars
    root = Path(project_path).resolve()
    target = (root / relative_file).resolve()
    if not str(target).startswith(str(root)):
        raise ValueError("Path traversal detectado")
    return target
```

---

## Controles de seguridad

### Confidencialidad

**Path traversal prevention** (`tools/code_context.py` + `tools/_validators.py`): dos capas — validación explícita (rechaza `..`, `~`, null bytes, shell chars) + verificación post-resolución (el path resuelto debe empezar con el project_root).

**Sanitización de outputs** (`tools/code_context.py`): `_mark_code_output()` añade `type: "code_snippet"` + `warning` a cada respuesta de código para mitigar prompt injection.

**Credential masking** (`audit.py`): `_mask_sensitive()` redacta `api_key`, `dt_api_key`, `anthropic_api_key`, `token`, `password`, `secret` → `***REDACTED***` en audit.log.

### Integridad

**Validación de inputs** (`tools/_validators.py`):

| Parámetro | Validación |
|---|---|
| `project_uuid` / UUIDs | Formato UUID v4 estricto |
| `project_path` | Absoluto, existente, sin null bytes ni `~` |
| `file_path` | Sin `..`, `~`, null bytes ni shell chars |
| `package_name` | Alfanuméricos + `-_/@.:+`, máx 200 chars |
| `vulnerability_id` | `^(CVE-\d{4}-\d{4,}\|GHSA-...)$` |
| `start_line` / `end_line` | `1 ≤ valor ≤ 100000`, `end ≥ start` |

**Inmutabilidad de verdicts** (`tools/reachability.py`):
```python
_STATE_HIERARCHY = {
    "NOT_SET": 0, "IN_TRIAGE": 1,
    "NOT_AFFECTED": 2, "FALSE_POSITIVE": 2,
    "EXPLOITABLE": 3,
}
```

**Hash de integridad VEX** (`tools/decision.py`): SHA-256 calculado ANTES de agregar el campo `integrity` para evitar circularidad.

**Rate limiting** (`tools/code_context.py`): contadores thread-safe por sesión.
```python
_RATE_LIMITS = {
    "fetch_code_snippet": 200,
    "get_function_context": 100,
    "get_call_context": 100,
    "find_symbol_usages": 50,
}
```

### Disponibilidad

**Timeouts httpx** (`clients/dependency_track.py`): `connect=5s / read=30s / write=10s / pool=5s`.

**`@safe_tool` decorator** (`audit.py`): `ValueError`/`TypeError` → `{"error": "validation_error"}`. Otras excepciones → traceback en audit.log, respuesta genérica al LLM.

**Paginación defensiva** (`tools/sbom_ingestion.py`): máx `MAX_FINDINGS_PER_RESPONSE` (default 50) por llamada con `offset`/`has_more`/`next_offset`.

**Fail-fast al arranque** (`main.py`): detecta SSE en `0.0.0.0`, `audit.log` world-writable, `.env` legible por otros.

---

## Observabilidad — audit.log

Cada tool call decorada con `@audit_tool` escribe una línea JSON:

```json
{
  "tool_name": "run_reachability_filter",
  "timestamp": "2025-04-22T10:31:05.123Z",
  "input": {"project_uuid": "ad5f9c55", "project_path": "/path/to/app", "dry_run": "True"},
  "duration_ms": 847,
  "output_hash": "a3f2b1c9",
  "side_effects": "external_write",
  "error": null
}
```

Las claves sensibles siempre se reemplazan con `"***REDACTED***"` antes de escribir.

---

## Integración actual: MCP + Dependency-Track

```
┌─────────────────────┐         ┌─────────────────────────────────────┐
│   Claude Desktop /  │  MCP    │         ZeroNoise                   │
│   Claude VSCode     │◄───────►│      (FastMCP server)               │
│   Extension         │  stdio  │                                     │
└─────────────────────┘         │  17 tools + 4 resources             │
                                 │                                     │
                                 │  ┌───────────────────────────┐     │
                                 │  │  Dependency-Track          │     │
                                 │  │  http://localhost:8080     │     │
                                 │  └───────────────────────────┘     │
                                 │                                     │
                                 │  ┌───────────────────────────┐     │
                                 │  │  Código fuente del proyecto│     │
                                 │  │  (filesystem local)        │     │
                                 │  └───────────────────────────┘     │
                                 │                                     │
                                 │  ┌───────────────────────────┐     │
                                 │  │  dep-check.json            │     │
                                 │  │  (reporte OWASP fast-gate) │     │
                                 │  └───────────────────────────┘     │
                                 └─────────────────────────────────────┘
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

---

## Integración en CI/CD

```
┌──────────────────────────────────────────────────────────────┐
│                       CI/CD Pipeline                          │
│                                                               │
│  build → test → owasp-dep-check ──► ZeroNoise ──► deploy    │
│                        │                  │                   │
│               dep-check.json    pipeline_decision             │
│                                    BLOCK/PROMOTE              │
└──────────────────────────────────────────────────────────────┘
```

**Trigger sugerido (GitHub Actions):**
```yaml
- name: OWASP Dependency Check
  run: |
    dependency-check --project myapp --out . --format JSON

- name: ZeroNoise security gate
  run: |
    uv run python scripts/poc_depcheck.py \
      --report dependency-check-report.json \
      --project-path ${{ github.workspace }} \
      --apply
    # El script retorna exit code 1 si pipeline_decision == BLOCK
```

---

## Lenguajes soportados y roadmap

| Lenguaje | Import Scanner | Stage 3 Patterns | Estado |
|---|---|---|---|
| JavaScript / TypeScript | ✅ js_import_scanner | ✅ Express/Node patterns | Completo |
| Java (Spring/Maven/Gradle) | ✅ java_import_scanner | ✅ Spring Boot patterns | Completo |
| Kotlin (.kt) | ✅ java_import_scanner | ✅ Spring Boot patterns | Completo |
| Python | ❌ Sin scanner | ❌ | Pendiente |
| Go | ❌ Sin scanner | ❌ | Pendiente |
| Rust | ❌ Sin scanner | ❌ | Pendiente |
| Jakarta EE / Quarkus | ✅ (mismo scanner Java) | ⚠️ Sin @PathParam/@QueryParam | Pendiente patterns |

---

## Limitaciones conocidas

| Limitación | Impacto | Workaround actual |
|---|---|---|
| Reflection / `Class.forName` no detectada | Falso negativo en deserialization gadgets | Documentado en `_LIMITATIONS`, requiere human review |
| Spring auto-configuration sin imports explícitos | Falso negativo para librerías autoconfigured | Stage 3 puede usarse manualmente con `--package` |
| Regex vs AST — falsos positivos en strings/comentarios | Bajo impacto en práctica | `get_call_context` documenta limitación |
| Confidencia heurística, no formal | NOT_REACHABLE < 0.70 requiere revisión humana | `requires_human_review` flag en resultado |
| Artefactos legacy sin mapping (javassist, cglib, woodstox) | Falso negativo para esas librerías | Agregar a `_LEGACY_IMPORT_MAPPINGS` |
| Stage 0 requiere artefacto compilado | `UNVERIFIABLE` si no hay fat JAR | Compilar antes de correr ZeroNoise |
| Stage 3 heurístico sin LLM | Puede producir REACHABLE sin veredicto final | Combinar con Stage 3 LLM manual |

---

## Glosario técnico

| Término | Definición |
|---|---|
| **MCP** | Model Context Protocol — protocolo de Anthropic para que LLMs invoquen tools externas |
| **SBOM** | Software Bill of Materials — lista de todas las dependencias de un proyecto |
| **SCA** | Software Composition Analysis — análisis de vulnerabilidades en dependencias |
| **PURL** | Package URL — identificador estándar: `pkg:maven/org.springframework/spring-core@5.3.0` |
| **Maven GAV** | GroupId:ArtifactId:Version — coordenadas de un paquete Maven |
| **VEX** | Vulnerability Exploitability eXchange — documento que justifica por qué una vuln no es explotable |
| **OpenVEX** | Implementación open source del estándar VEX |
| **Fat JAR** | JAR que contiene todas sus dependencias empaquetadas (ej: Spring Boot uber JAR) |
| **Reachability** | Si existe un camino de ejecución real desde el código hasta la función vulnerable |
| **Stage 3 Gate** | Condición triple: verdict=REACHABLE + evidence≠∅ + confidence≥0.70 |
| **Noise reduction %** | Porcentaje de findings eliminados automáticamente (NOT_REACHABLE / total_actionable) |
| **Dry run** | Modo que analiza pero no escribe en Dependency-Track |
| **Starter wrapper** | Dependencia de Spring Boot que declara versión ≠ versión de la librería real incluida |
