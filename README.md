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

> **Estado del Proyecto:** En desarrollo. Implementando servidores MCP para integración con repositorios Git y conectores de Dependency-Track.