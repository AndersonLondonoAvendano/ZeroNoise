"""
poc_depcheck.py — POC: flujo completo dep-check → Stage 2 → Stage 3.

Punto de prueba sin pipeline de CI/CD. Replica lo que hará el fast-gate
cuando el pipeline entregue el reporte de dep-check a ZeroNoise.

Uso:
    # Análisis básico (dry-run, threshold del .env o 7.0)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/dependency-check-report.json \\
        --project-path /ruta/al/codigo/fuente

    # Con threshold personalizado
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --cvss-threshold 9.0

    # Aplicar verdicts en DT (escritura real)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --apply

    # Solo diagnóstico del reporte (sin correr stages)
    uv run python scripts/poc_depcheck.py \\
        --report /ruta/report.json \\
        --project-path /ruta/fuente \\
        --diagnose-only
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path


async def run_diagnose_only(report_path: str, threshold: float) -> None:
    """Solo imprime el diagnóstico del ingester sin correr Stage 2/3."""
    from zeronoise.clients.depcheck_ingester import DepCheckIngester

    ingester = DepCheckIngester(report_path)
    meta = ingester.get_report_metadata()
    all_findings = ingester.load()
    blockers = ingester.filter_by_cvss(all_findings, threshold)

    print(f"\n{'='*60}")
    print(f"  DIAGNÓSTICO — {meta['project_name']}")
    print(f"  Scanner: {meta['scanner_version']} | Schema: {meta['schema_version']}")
    print(f"  Fecha:   {meta['report_date']}")
    print(f"{'='*60}")
    print(f"  Total deps:       {meta['total_dependencies']}")
    print(f"  Con vulns:        {meta['dependencies_with_vulns']}")
    print(f"  CVEs únicos:      {len(all_findings)}")
    print(f"  Gate blockers (CVSS >= {threshold}):  {len(blockers)}")
    print()

    for f in all_findings:
        is_blocker = f in blockers
        marker = "BLOCKER" if is_blocker else "no blocker"
        score_str = f"{f.cvss.score} ({f.cvss.source.value})" if f.cvss else "sin score"
        purl_str = f.effective_purl or "NO PURL"
        conf_str = (
            f.primary_package.purl_confidence.value if f.primary_package else "N/A"
        )
        n_jars = len(f.affected_packages)

        print(f"  [{marker}] {f.cve_id}  CVSS: {score_str}  {f.severity}")
        print(f"    PURL ({conf_str}): {purl_str}")
        print(f"    JARs afectados: {n_jars}")
        for p in f.affected_packages:
            shaded = " [SHADED]" if p.shadowed_dependency else ""
            mismatch = " [CPE_MISMATCH]" if p.cpe_version_mismatch else ""
            print(f"      · {p.file_name}{shaded}{mismatch}")
        if f.identification_issues:
            print(f"    Issues:")
            for issue in f.identification_issues:
                print(f"      · {issue}")
        if f.requires_human_review:
            print(f"    REQUIERE REVISION HUMANA")
        print()


async def run_full_analysis(
    report_path: str,
    project_path: str,
    threshold: float,
    apply: bool,
) -> None:
    """Ejecuta el flujo completo: dep-check → Stage 2 → Stage 3."""
    from fastmcp import Client
    from zeronoise.server import mcp

    print(f"\nIniciando análisis ZeroNoise...")
    print(f"   Reporte:  {report_path}")
    print(f"   Proyecto: {project_path}")
    print(f"   Umbral:   CVSS >= {threshold}")
    print(f"   Modo:     {'APPLY (escribe en DT)' if apply else 'DRY-RUN'}")
    print()

    async with Client(mcp) as client:
        result = await client.call_tool(
            "analyze_depcheck_report",
            {
                "report_path": report_path,
                "project_path": project_path,
                "cvss_threshold": threshold,
                "dry_run": not apply,
            },
        )

    raw = result.content[0].text if (result and result.content) else "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print(f"Error parseando resultado: {raw}")
        sys.exit(1)

    if data.get("error"):
        print(f"Error: {data.get('message', data.get('error'))}")
        sys.exit(1)

    decision = data.get("pipeline_decision", "UNKNOWN")
    summary = data.get("summary", {})

    print(f"{'='*60}")
    print(f"  RESULTADO ZERONOISE")
    print(f"{'='*60}")
    decision_label = "PROMOTE" if decision == "PROMOTE" else "BLOCK"
    print(f"  Pipeline decision: {decision_label}")
    print()
    print(f"  Gate blockers encontrados: {summary.get('gate_blockers_found', 0)}")
    print(f"  NOT_REACHABLE (0 tokens):  {summary.get('not_reachable', 0)}")
    print(f"  Analizados (Stage 3):      {summary.get('reachable', 0)}")
    print(f"  EXPLOITABLE/LIKELY:        {summary.get('exploitable', 0)}")
    print(f"  UNKNOWN (revisión humana): {summary.get('unknown', 0)}")
    print(f"  {summary.get('tokens_used', '')}")
    print()

    icons = {
        "NOT_REACHABLE": "[OK ]",
        "FALSE_POSITIVE": "[OK ]",
        "REACHABLE":      "[!!]",
        "LIKELY_EXPLOITABLE": "[XX]",
        "EXPLOITABLE":    "[XX]",
        "UNKNOWN":        "[??]",
    }

    print("  Verdicts por CVE:")
    for v in data.get("verdicts", []):
        verdict = v.get("verdict", "UNKNOWN")
        icon = icons.get(verdict, "[??]")
        print(f"  {icon} {v.get('cve_id')} -> {verdict}")
        print(f"     Paquete: {v.get('package')} (PURL {v.get('purl_confidence')})")
        justification = v.get("justification", "")
        if justification:
            print(f"     {justification[:200]}")
        if v.get("requires_human_review"):
            print(f"     [REVISION HUMANA REQUERIDA]")
        for issue in v.get("identification_issues", []):
            print(f"     ISSUE: {issue}")
        print()

    if decision == "BLOCK":
        print(f"  BLOCK reason: {data.get('block_reason')}")
    else:
        print(f"  PROMOTE reason: {data.get('promote_reason')}")

    output_path = Path("depcheck_gate_result.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n  Resultado completo guardado en: {output_path}")

    sys.exit(0 if decision == "PROMOTE" else 1)


def main():
    parser = argparse.ArgumentParser(
        description="ZeroNoise — Análisis de reporte OWASP Dependency-Check"
    )
    parser.add_argument(
        "--report", required=True,
        help="Ruta al reporte JSON de dep-check"
    )
    parser.add_argument(
        "--project-path", required=True,
        help="Ruta al código fuente del proyecto"
    )
    parser.add_argument(
        "--cvss-threshold", type=float, default=None,
        help="Umbral CVSS (default: GATE_CVSS_THRESHOLD del .env o 7.0)"
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Escribir verdicts en DT (default: dry-run)"
    )
    parser.add_argument(
        "--diagnose-only", action="store_true",
        help="Solo diagnosticar el reporte sin correr Stage 2/3"
    )
    args = parser.parse_args()

    threshold = args.cvss_threshold
    if threshold is None:
        try:
            from zeronoise.config import get_settings
            threshold = get_settings().gate_cvss_threshold
        except Exception:
            threshold = 7.0

    if args.diagnose_only:
        asyncio.run(run_diagnose_only(args.report, threshold))
    else:
        asyncio.run(run_full_analysis(
            report_path=args.report,
            project_path=args.project_path,
            threshold=threshold,
            apply=args.apply,
        ))


if __name__ == "__main__":
    main()
