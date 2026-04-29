# Tarea 08 — B3: POC Velocidad 2 (analyze_project_vulnerabilities)

**Archivo a crear:** `scripts/poc_dt_background.py`
**Tiempo estimado:** 15 minutos
**Dependencias:** Tarea 07 implementada

---

## Crear `scripts/poc_dt_background.py`

```python
"""
poc_dt_background.py — POC Velocidad 2: análisis background desde Dependency-Track.

Uso:
    # Análisis dry-run (solo HIGH y CRITICAL, máx 20 findings)
    uv run python scripts/poc_dt_background.py \\
        --project-uuid 0dd02b59-c900-4bdd-bfda-6539ec040562 \\
        --project-path C:\\ruta\\al\\codigo\\fuente

    # Solo CRITICAL, máx 5
    uv run python scripts/poc_dt_background.py \\
        --project-uuid 0dd02b59-... \\
        --project-path C:\\ruta\\fuente \\
        --severity-filter CRITICAL \\
        --max-findings 5

    # Todos los findings (ALL)
    uv run python scripts/poc_dt_background.py \\
        --project-uuid 0dd02b59-... \\
        --project-path C:\\ruta\\fuente \\
        --severity-filter ALL

    # Paginación — continuar desde el finding 20
    uv run python scripts/poc_dt_background.py \\
        --project-uuid 0dd02b59-... \\
        --project-path C:\\ruta\\fuente \\
        --offset 20

    # Aplicar verdicts en DT (escritura real)
    uv run python scripts/poc_dt_background.py \\
        --project-uuid 0dd02b59-... \\
        --project-path C:\\ruta\\fuente \\
        --apply
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

from fastmcp import Client
from zeronoise.server import mcp


async def run(args):
    print(f"\n🔍 ZeroNoise — Velocidad 2 (análisis background DT)")
    print(f"   Proyecto UUID: {args.project_uuid}")
    print(f"   Código fuente: {args.project_path}")
    print(f"   Severidad:     {args.severity_filter}")
    print(f"   Máx findings:  {args.max_findings}")
    print(f"   Modo:          {'APPLY' if args.apply else 'DRY-RUN'}")
    if args.offset:
        print(f"   Offset:        {args.offset}")
    print()

    async with Client(mcp) as client:
        result = await client.call_tool(
            "analyze_project_vulnerabilities",
            {
                "project_uuid": args.project_uuid,
                "project_path": args.project_path,
                "max_findings": args.max_findings,
                "severity_filter": args.severity_filter,
                "dry_run": not args.apply,
                "offset": args.offset,
            },
        )

    raw = result[0].text if result else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"❌ Error parseando resultado:\n{raw}")
        sys.exit(1)

    # Resumen
    decision = data.get("pipeline_decision", "UNKNOWN")
    summary = data.get("summary", {})
    icon = "✅ PROMOTE" if decision == "PROMOTE" else "❌ BLOCK"

    print(f"{'='*60}")
    print(f"  {data.get('project_name', 'unknown')} — {icon}")
    print(f"{'='*60}")
    print(f"  Actionable en DT:    {summary.get('total_actionable', 0)}")
    print(f"  Analizados:          {summary.get('analyzed', 0)}")
    print(f"  Restantes:           {summary.get('remaining', 0)}")
    print(f"  NOT_REACHABLE:       {summary.get('not_reachable', 0)}")
    print(f"  REACHABLE/otros:     {summary.get('reachable', 0)}")
    print(f"  EXPLOITABLE:         {summary.get('exploitable', 0)}")
    print(f"  Reducción de ruido:  {summary.get('noise_reduction_pct', 0)}%")
    print(f"  {summary.get('tokens_used', '')}")
    print()

    # Verdicts
    for v in data.get("verdicts", []):
        verdict = v.get("verdict", "UNKNOWN")
        icons = {
            "NOT_REACHABLE": "🟢", "FALSE_POSITIVE": "🟢",
            "REACHABLE": "🟡", "LIKELY_EXPLOITABLE": "🔴",
            "EXPLOITABLE": "🔴", "UNKNOWN": "⚪",
        }
        print(f"  {icons.get(verdict, '⚪')} {v.get('cve_id')} — {verdict}")
        print(f"     {v.get('package')} | Stage3: {'Sí' if v.get('stage3_used') else 'No'}")
        justification = v.get("justification", "")
        if justification:
            print(f"     {justification[:180]}")
        print()

    if data.get("continuation_hint"):
        print(f"  ℹ️  {data['continuation_hint']}")

    # Guardar JSON
    out = Path("dt_background_result.json")
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    print(f"\n  Resultado completo guardado en: {out}")

    sys.exit(0 if decision in ("PROMOTE", "REVIEW") else 1)


def main():
    p = argparse.ArgumentParser(description="ZeroNoise — Velocidad 2: análisis background DT")
    p.add_argument("--project-uuid", required=True)
    p.add_argument("--project-path", required=True)
    p.add_argument("--max-findings", type=int, default=20)
    p.add_argument("--severity-filter", default="HIGH",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"])
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--apply", action="store_true",
                   help="Escribir verdicts en DT (default: dry-run)")
    args = p.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
```

## Comandos de prueba

```bash
# Proyecto clientes — dry-run
uv run python scripts/poc_dt_background.py \
    --project-uuid 0dd02b59-c900-4bdd-bfda-6539ec040562 \
    --project-path C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes

# Solo CRITICAL
uv run python scripts/poc_dt_background.py \
    --project-uuid 0dd02b59-c900-4bdd-bfda-6539ec040562 \
    --project-path C:\...\microservicio-clientes \
    --severity-filter CRITICAL

# WebGoat
uv run python scripts/poc_dt_background.py \
    --project-uuid ce2cf25e-25ef-44d5-b3e6-4e1ef708b190 \
    --project-path C:\...\WebGoat
```

## Prompt para el agente de Teams

Una vez conectado ZeroNoise a Copilot Studio, el equipo de seguridad puede escribir:

> Analiza las vulnerabilidades pendientes del proyecto clientes (UUID:
> `0dd02b59-c900-4bdd-bfda-6539ec040562`) con código fuente en
> `C:\...\microservicio-clientes`. Solo HIGH y CRITICAL, dry-run.

## Lo que NO tocar

Ningún archivo existente.
