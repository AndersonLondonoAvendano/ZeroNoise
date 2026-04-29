# Tarea 06 — B1+B2: POC verificación de artefacto

**Archivo a crear:** `scripts/poc_artifact_verify.py`
**Tiempo estimado:** 15 minutos
**Dependencias:** Tareas 03 y 04 implementadas

---

## Qué hace

Script standalone para probar Stage 0 de forma aislada, sin correr Stage 2/3.
Permite verificar que el ArtifactInspector y el DependencyTreeParser funcionan
correctamente con el proyecto real antes de integrarlos al flujo completo.

## Crear `scripts/poc_artifact_verify.py`

```python
"""
poc_artifact_verify.py — Verifica versiones de artefacto y árbol de dependencias.

Prueba Stage 0 de forma aislada.

Uso:
    # Diagnóstico completo del proyecto
    uv run python scripts/poc_artifact_verify.py \\
        --project-path C:\\ruta\\al\\proyecto

    # Paquete específico
    uv run python scripts/poc_artifact_verify.py \\
        --project-path C:\\ruta\\proyecto \\
        --package thymeleaf \\
        --reported-version 3.4.6

    # Contra reporte dep-check completo
    uv run python scripts/poc_artifact_verify.py \\
        --project-path C:\\ruta\\proyecto \\
        --report C:\\ruta\\dependency-check-report.json
"""
import argparse
import json
from pathlib import Path

from zeronoise.analyzers.artifact_inspector import ArtifactInspector
from zeronoise.analyzers.dependency_tree_parser import DependencyTreeParser


def _header(project_path: str, inspector: ArtifactInspector, parser: DependencyTreeParser):
    artifact = inspector.find_artifact()
    tool = parser.detect_build_tool()
    print(f"\n{'='*60}")
    print(f"  Proyecto:   {project_path}")
    print(f"  Artefacto:  {artifact.name if artifact else 'NO ENCONTRADO'}")
    print(f"  Build tool: {tool or 'NO DETECTADO'}")
    print(f"{'='*60}\n")


def run_single(project_path: str, package: str, reported_version: str):
    inspector = ArtifactInspector(project_path)
    parser = DependencyTreeParser(project_path)
    _header(project_path, inspector, parser)

    av = inspector.verify_version(package, reported_version)
    tv = parser.verify_version(package, reported_version)

    print(f"  Artefacto JAR: {av.summary}")
    print(f"  Dep tree:      {tv.summary}")
    if av.analysis_note:
        print(f"\n  📋 {av.analysis_note}")
    if tv.analysis_note and tv.analysis_note != av.analysis_note:
        print(f"  📋 {tv.analysis_note}")
    if tv.is_starter_wrapper:
        print(f"\n  ⚠️  STARTER WRAPPER: '{package}' → librería real: "
              f"'{tv.actual_library_name}@{tv.real_version}'")


def run_with_report(project_path: str, report_path: str):
    from zeronoise.clients.depcheck_ingester import DepCheckIngester

    ingester = DepCheckIngester(report_path)
    findings = ingester.load()
    inspector = ArtifactInspector(project_path)
    parser = DependencyTreeParser(project_path)
    _header(project_path, inspector, parser)

    print(f"  CVEs únicos a verificar: {len(findings)}\n")
    results = []

    for f in findings:
        if not f.primary_package:
            continue
        name = f.primary_package.artifact_name
        version = f.primary_package.artifact_version

        av = inspector.verify_version(name, version)
        tv = parser.verify_version(name, version)
        flag = "⚠️ " if (av.requires_reanalysis or tv.requires_reanalysis) else "   "

        print(f"  {flag}{f.cve_id} — {name}@{version}")
        print(f"      JAR:  {av.verdict.value} → {av.real_version or 'N/A'}")
        print(f"      Tree: {tv.verdict.value} → {tv.real_version or 'N/A'}")
        if tv.is_starter_wrapper:
            print(f"      Starter → real: {tv.actual_library_name}@{tv.real_version}")
        if av.requires_reanalysis or tv.requires_reanalysis:
            note = tv.analysis_note or av.analysis_note
            if note:
                print(f"      📋 {note[:120]}")
        print()

        results.append({
            "cve_id": f.cve_id,
            "package": name,
            "reported_version": version,
            "artifact_verdict": av.verdict.value,
            "tree_verdict": tv.verdict.value,
            "real_version": tv.real_version or av.real_version,
            "requires_reanalysis": av.requires_reanalysis or tv.requires_reanalysis,
            "is_starter_wrapper": tv.is_starter_wrapper,
        })

    out = Path("artifact_verification_result.json")
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(f"  Resultado guardado en: {out}")


def main():
    p = argparse.ArgumentParser(description="ZeroNoise — Stage 0: verificación de artefacto")
    p.add_argument("--project-path", required=True)
    p.add_argument("--package", default=None)
    p.add_argument("--reported-version", default=None)
    p.add_argument("--report", default=None)
    args = p.parse_args()

    if args.report:
        run_with_report(args.project_path, args.report)
    elif args.package and args.reported_version:
        run_single(args.project_path, args.package, args.reported_version)
    else:
        # Sin argumentos específicos: diagnóstico del artefacto solamente
        inspector = ArtifactInspector(args.project_path)
        parser = DependencyTreeParser(args.project_path)
        _header(args.project_path, inspector, parser)
        artifact = inspector.find_artifact()
        if artifact:
            idx = inspector.build_jar_index(artifact)
            print(f"  JARs internos indexados: {len(idx)}")
            for name, av in list(idx.items())[:10]:
                print(f"    {av.artifact_name}@{av.resolved_version} [{av.source}]")
            if len(idx) > 10:
                print(f"    ... y {len(idx)-10} más")


if __name__ == "__main__":
    main()
```

## Comandos de prueba

```bash
# 1. Solo diagnóstico del artefacto
uv run python scripts/poc_artifact_verify.py \
    --project-path C:\Users\admin\Desktop\ZeroNoise\vuln_projects\clientes-develop\microservicio-clientes

# 2. Caso Thymeleaf específico
uv run python scripts/poc_artifact_verify.py \
    --project-path C:\...\microservicio-clientes \
    --package thymeleaf \
    --reported-version 3.4.6

# 3. Contra el reporte dep-check
uv run python scripts/poc_artifact_verify.py \
    --project-path C:\...\microservicio-clientes \
    --report C:\Users\admin\Desktop\ZeroNoise\dependency-check-report.json
```

## Lo que NO tocar

Ningún archivo existente.
