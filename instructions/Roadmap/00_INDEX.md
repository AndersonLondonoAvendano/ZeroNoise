# ZeroNoise — Índice de Implementación

> Entregar cada archivo a Claude Code en una sesión separada, en el orden indicado.
> Cada archivo es autónomo — no depende de que el anterior esté en contexto.

## Orden de entrega

| Orden | Archivo | Brecha | Dependencias |
|---|---|---|---|
| 1 | `01_B8_kotlin.md` | Kotlin scanner — 1 línea | Ninguna |
| 2 | `02_B1B2_models.md` | Modelos Stage 0 | Ninguna |
| 3 | `03_B1B2_artifact_inspector.md` | Inspector JAR | `02` implementado |
| 4 | `04_B1B2_deptree_parser.md` | Parser árbol deps | `02` implementado |
| 5 | `05_B1B2_stage0_integration.md` | Stage 0 en depcheck_gate | `03` y `04` implementados |
| 6 | `06_B1B2_poc_artifact.md` | POC verificación artefacto | `03` y `04` implementados |
| 7 | `07_B3_dt_background.md` | Tool analyze_project_vulnerabilities | Ninguna |
| 8 | `08_B3_poc_dt_background.md` | POC Velocidad 2 | `07` implementado |
| 9 | `09_B4_sse_auth.md` | SSE + API Key + /health | Ninguna |
| 10 | `10_B7_notifier.md` | Notificaciones Teams webhook | `07` implementado |
| 11 | `11_B5_git_client.md` | Git client servidor remoto | Ninguna |
| 12 | `12_B6_scheduler.md` | Scheduler automático | `07` y `11` implementados |

## Estado (marcar al completar)

- [ HECHO ] 01 B8 Kotlin
- [ HECHO ] 02 B1B2 Models
- [ HECHO ] 03 B1B2 Artifact Inspector
- [ HECHO ] 04 B1B2 Dep Tree Parser
- [ HECHO ] 05 B1B2 Stage 0 Integration
- [ ] 06 B1B2 POC Artifact
- [ ] 07 B3 DT Background Tool
- [ ] 08 B3 POC DT Background
- [ ] 09 B4 SSE Auth
- [ ] 10 B7 Notifier
- [ ] 11 B5 Git Client
- [ ] 12 B6 Scheduler
