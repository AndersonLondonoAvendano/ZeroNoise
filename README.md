# ZeroNoise

**ZeroNoise** es un motor de auditoría inteligente diseñado para eliminar el ruido y los falsos positivos en la gestión de vulnerabilidades. A diferencia de los escaneos tradicionales que solo reportan la presencia de una librería vulnerable, ZeroNoise utiliza Inteligencia Artificial y **Model Context Protocol (MCP)** para determinar la **explotabilidad real** basándose en el contexto específico de tu proyecto.

## La Filosofía: "La IA como Auditor, no como Lector"

El problema común en la automatización con LLMs es el alto consumo de tokens y la pérdida de foco al procesar bases de código completas. ZeroNoise resuelve esto mediante un enfoque de **Investigación Bajo Demanda**:

> "La IA no debe leer todo tu código; debe preguntar por lo que necesita saber."

## Estrategia de Reducción de Ruido

ZeroNoise opera en cuatro capas lógicas para optimizar la precisión y el costo:

### 0. Verificación de Artefacto (Stage 0)
Antes de analizar cualquier CVE, verifica que la versión reportada por el scanner coincida con la versión **realmente empaquetada** en el fat JAR compilado y resuelta en el árbol de dependencias. Detecta:
- Mismatches entre versión reportada y versión real
- Starters de Spring Boot (la versión del starter ≠ la versión de la librería real)
- Dependencias NOT_FOUND en el runtime (posibles falsos positivos)

### 1. Filtro de Entrada (Metadata-First)
En lugar de procesar archivos fuente, el sistema ingiere metadatos del **SBOM** (vía Dependency-Track) o del reporte JSON de **OWASP Dependency-Check**. Identificamos el CVE y el punto de entrada específico (función o clase) que contiene la vulnerabilidad.

### 2. Análisis de Alcanzabilidad (Reachability)
Análisis estático basado en regex sobre el código fuente.
* **La pregunta:** ¿Existe un import real de este paquete en el código de la aplicación?
* **El resultado:** Si el paquete nunca se importa, la vulnerabilidad se marca automáticamente como `Not Affected` sin consumir tokens de análisis de código.

### 3. Deep Dive Contextual (Vía MCP)
Si el paquete es alcanzable, la IA utiliza **Model Context Protocol (MCP)** para "auditar" fragmentos específicos:
* Solicita solo los fragmentos de código relevantes (snippets).
* Analiza si las entradas de usuario están sanitizadas.
* Evalúa el entorno (controles de red, privilegios, exposición).

---

## Arquitectura de la Solución

| Componente | Función | Impacto en Tokens |
| :--- | :--- | :--- |
| **ArtifactInspector (Stage 0)** | Verifica la versión real empaquetada en el fat JAR vs. la versión reportada. Detecta mismatches y falsos positivos por versión. | **Cero** (filesystem local) |
| **DependencyTreeParser (Stage 0)** | Parsea el árbol de dependencias Maven/Gradle. Resuelve la versión efectiva para starters y transitive deps. Genera el árbol automáticamente si no existe. | **Cero** (filesystem local) |
| **SCA (Dependency-Track / OWASP Dep-Check)** | Ingesta de SBOM y detección de CVEs desde dos fuentes. | **Cero** (API local / archivo JSON) |
| **ImportScanner (Stage 2)** | Análisis regex de importaciones en JavaScript/TypeScript, Java y Kotlin. | **Cero** |
| **ProjectContextReader** | Lee README, configuración de build y YAML de la aplicación para enriquecer el contexto del LLM. | **Cero** (filesystem local) |
| **Orquestador (MCP)** | Decide qué CVEs investigar según el análisis de alcanzabilidad. | **Mínimo** (Metadatos JSON) |
| **Agente de Auditoría (Stage 3)** | Inspección lógica de fragmentos de código con señales pre-análisis. | **Moderado** (Snippets específicos) |

---

## Dos Frentes Operacionales

### Frente 1 — Dependency-Track (post-SBOM)
Consume findings directamente desde la API de DT. Útil cuando DT ya está integrado en el pipeline.

```
DT API → Stage 1 → Stage 0 → Stage 2 → Stage 3 → VEX Report
```

Tool: `analyze_project_vulnerabilities`

### Frente 2 — OWASP Dependency-Check (fast-gate de CI/CD)
Consume el reporte JSON generado por OWASP Dep-Check directamente en el pipeline, sin servidor externo.

```
dep-check.json → Stage 0 → Stage 2 → Stage 3 → pipeline_decision (BLOCK | PROMOTE)
```

Tool: `analyze_depcheck_report`

---

## Integración en el Pipeline (The Gatekeeper)

ZeroNoise actúa como un **Security Gatekeeper** en tu flujo de CI/CD:

1. **Trigger:** Se activa cuando un scan de seguridad detecta vulnerabilidades críticas.
2. **Evaluación:** La IA audita la alcanzabilidad y el contexto.
3. **Veredicto:**
   * ✅ **Promote:** Genera un archivo **VEX (Vulnerability Exploitability eXchange)** justificando el falso positivo y permitiendo el despliegue.
   * ❌ **Block:** Confirma el riesgo real y detiene el pipeline con un informe técnico detallado.

---

## Objetivos del Proyecto

* **Cero Falsos Positivos:** Reducir la carga de trabajo manual del equipo de seguridad.
* **Justificación de Riesgo:** No solo entregamos un score, entregamos un "por qué".
* **Eficiencia Operativa:** Reducir los tiempos de entrega (Time-to-Market) al evitar bloqueos innecesarios en el pipeline.
* **Estándares Abiertos:** Generación de reportes en formato VEX para interoperabilidad con el ecosistema de ciberseguridad.

---

## Seguridad del Motor

ZeroNoise analiza código fuente empresarial confidencial y es consumido por LLMs externos. Los controles de seguridad implementados cubren tres dominios:

### Confidencialidad
* **Path traversal prevention** — Todas las rutas de filesystem pasan por validación multicapa: rechazo explícito de `..`, `~`, null bytes y shell chars, más verificación post-resolución contra el project root.
* **Sanitización anti prompt-injection** — Los snippets de código retornados al LLM llevan `type: "code_snippet"` y un campo `warning` explícito para que el modelo los trate como datos, no como instrucciones.
* **Credential masking en audit.log** — Las claves sensibles (`api_key`, `token`, `password`, etc.) se reemplazan con `***REDACTED***` antes de escribir en el log de auditoría.
* **Permisos restrictivos** — `audit.log` se crea con `chmod 0o600` al arrancar el servidor.

### Integridad
* **Validación estricta de inputs** — UUID v4, paths absolutos existentes, IDs de vulnerabilidad en formato CVE/GHSA, rangos de líneas acotados. Implementado en `tools/_validators.py` y aplicado al inicio de cada tool.
* **Inmutabilidad de verdicts** — Los estados de análisis solo pueden avanzar en severidad (`NOT_SET → IN_TRIAGE → NOT_AFFECTED → EXPLOITABLE`). Un EXPLOITABLE nunca puede ser revertido a NOT_AFFECTED.
* **Hash de integridad VEX** — El reporte OpenVEX que autoriza o bloquea el deploy incluye un SHA-256 de su contenido para detección de tampering.
* **Rate limiting por sesión** — Las tools de acceso a código (`fetch_code_snippet`, `get_function_context`, etc.) tienen límites de invocación por sesión MCP para prevenir exfiltración de código en bucle.

### Disponibilidad
* **Timeouts httpx estructurados** — `connect: 5s / read: 30s / write: 10s / pool: 5s` en todas las llamadas a Dependency-Track.
* **`@safe_tool` decorator** — Ninguna excepción no manejada puede crashear el servidor MCP. Los errores se convierten en respuestas estructuradas y se loggean internamente.
* **Paginación defensiva** — Stage 1 retorna máximo 50 findings por llamada (configurable) para evitar saturar el contexto del LLM consumidor.
* **Fail-fast al arranque** — El servidor detecta configuraciones inseguras (SSE en `0.0.0.0`, `.env` con permisos excesivos) antes de aceptar conexiones.

---

> **Estado del Proyecto:** Stage 0 (verificación de artefacto + árbol de dependencias), Stage 1, Stage 2 y Stage 3 implementados y validados. Dos frentes operacionales: Dependency-Track y OWASP Dep-Check. 17 MCP tools + 4 resources. Lenguajes soportados: JavaScript/TypeScript, Java (Spring/Maven/Gradle) y Kotlin.
