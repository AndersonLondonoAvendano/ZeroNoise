# ZeroNoise 🛡️

**ZeroNoise** es un motor de auditoría inteligente diseñado para eliminar el ruido y los falsos positivos en la gestión de vulnerabilidades. A diferencia de los escaneos tradicionales que solo reportan la presencia de una librería vulnerable, ZeroNoise utiliza Inteligencia Artificial y **Model Context Protocol (MCP)** para determinar la **explotabilidad real** basándose en el contexto específico de tu proyecto.

## La Filosofía: "La IA como Auditor, no como Lector"

El problema común en la automatización con LLMs es el alto consumo de tokens y la pérdida de foco al procesar bases de código completas. ZeroNoise resuelve esto mediante un enfoque de **Investigación Bajo Demanda**:

> "La IA no debe leer todo tu código; debe preguntar por lo que necesita saber."

## Estrategia de Reducción de Ruido

ZeroNoise opera en tres capas lógicas para optimizar la precisión y el costo:

### 1. Filtro de Entrada (Metadata-First)
En lugar de procesar archivos fuente, el sistema ingiere metadatos del **SBOM** (vía Dependency-Track). Identificamos el CVE y, lo más importante, el punto de entrada específico (función o clase) que contiene la vulnerabilidad.

### 2. Análisis de Alcanzabilidad (Reachability)
Utilizamos herramientas de análisis estático (**Semgrep** / **CodeQL**) para generar un **Call Graph**. 
* **La pregunta:** ¿Existe una ruta de ejecución real en nuestro código que invoque la función vulnerable?
* **El resultado:** Si la función nunca se llama, la vulnerabilidad se marca automáticamente como `Not Affected` sin consumir tokens de análisis de código.

### 3. Deep Dive Contextual (Vía MCP)
Si la función es alcanzable, la IA utiliza **Model Context Protocol (MCP)** para "auditar" fragmentos específicos:
* Solicita solo los fragmentos de código relevantes (snippets).
* Analiza si las entradas de usuario están sanitizadas.
* Evalúa el entorno (controles de red, privilegios, exposición).

---

## 🏗️ Arquitectura de la Solución

| Componente | Función | Impacto en Tokens |
| :--- | :--- | :--- |
| **Artifact Inspector (Stage 0)** | Verifica la versión real empaquetada en el fat JAR vs. la versión reportada por el scanner. Detecta mismatches y falsos positivos por versión antes de Stage 1. | **Cero** (filesystem local) |
| **SCA (Dependency-Track)** | Ingesta de SBOM y detección de CVEs. | **Cero** (API local) |
| **Static Analyzer** | Generación de Call Graph (Mapa de llamadas). | **Cero** |
| **Orquestador (MCP)** | Decide qué CVEs investigar según el mapa. | **Mínimo** (Metadatos JSON) |
| **Agente de Auditoría** | Inspección lógica de fragmentos de código. | **Moderado** (Snippets específicos) |

---

## 🛠️ Integración en el Pipeline (The Gatekeeper)

ZeroNoise actúa como un **Security Gatekeeper** en tu flujo de CI/CD:

1. **Trigger:** Se activa cuando un scan de seguridad detecta vulnerabilidades críticas.
2. **Evaluación:** La IA audita la alcanzabilidad y el contexto.
3. **Veredicto:** * ✅ **Promote:** Genera un archivo **VEX (Vulnerability Exploitability eXchange)** justificando el falso positivo y permitiendo el despliegue.
   * ❌ **Block:** Confirma el riesgo real y detiene el pipeline con un informe técnico detallado.

---

## 🎯 Objetivos del Proyecto

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

> **Estado del Proyecto:** Stage 0 (verificación de artefacto), Stage 1, Stage 2 y Stage 3 implementados y validados. Controles de seguridad CIA implementados. Lenguajes soportados: JavaScript/TypeScript, Java (Spring/Maven/Gradle) y Kotlin.