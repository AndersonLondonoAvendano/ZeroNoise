"""
depcheck_ingester.py — Lee el reporte JSON de OWASP Dependency-Check.

IMPORTANTE: Este ingester está diseñado para ser TOLERANTE a variaciones del
reporte. El formato del reporte de dep-check NO es estable entre versiones del
scanner, proyectos o configuraciones. Nunca asumir que un campo estará presente.

Casos manejados:
  CASO 1: PURL presente en packages[] → usar directamente (confianza HIGH)
  CASO 2: Sin PURL, nombre de artifact estándar Maven → reconstruir (confianza MEDIUM)
  CASO 3: Sin PURL, fat JAR con dep shadeada → reconstruir con warning (confianza LOW)
  CASO 4: Sin CVSS v3, solo v2 → fallback con flag (no bloquear automáticamente)
  CASO 5: Mismo CVE en múltiples JARs → deduplicar, conservar todos los paquetes
  CASO 6: CVE sin ningún score → marcar requires_human_review, no evaluar por umbral

Para ejecutar standalone (diagnóstico):
    python -m zeronoise.clients.depcheck_ingester path/to/report.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Optional

from zeronoise.models.depcheck_finding import (
    AffectedPackage, DepCheckCvss, DepCheckFinding,
    CvssSource, PurlConfidence,
)


# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------

# Extrae JAR interno de nombres como:
#   "microservicio-0.0.1-SNAPSHOT.jar: netty-resolver-dns-4.1.128.Final.jar"
_NESTED_JAR_RE = re.compile(r'^.+?\.(?:jar|war|ear):\s*(.+)$')

# Extrae artifact y version del nombre del JAR:
#   "netty-resolver-dns-4.1.128.Final.jar" → ("netty-resolver-dns", "4.1.128.Final")
#   "protobuf-java-3.25.8.jar"             → ("protobuf-java", "3.25.8")
#   "spring-amqp-3.2.8.jar"               → ("spring-amqp", "3.2.8")
_JAR_NAME_RE = re.compile(
    r'^(.+?)-(\d[\d.]*(?:\.(?:Final|RELEASE|GA|Alpha\d*|Beta\d*|RC\d*))?)\.jar$',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Mapping artifact → (groupId, artifactId) para reconstrucción de PURL
#
# IMPORTANTE: Esta tabla crece con el tiempo. Si el scanner encuentra un
# artifact que no está aquí, el PURL tendrá confianza LOW o UNAVAILABLE.
# Agregar nuevos mappings cuando se encuentren en proyectos reales.
# ---------------------------------------------------------------------------
_KNOWN_MAVEN_ARTIFACTS: dict[str, tuple[str, str]] = {
    # gRPC
    "grpc-netty-shaded":                ("io.grpc",                           "grpc-netty-shaded"),
    "grpc-core":                        ("io.grpc",                           "grpc-core"),
    "grpc-stub":                        ("io.grpc",                           "grpc-stub"),
    "grpc-protobuf":                    ("io.grpc",                           "grpc-protobuf"),
    # Reactor Netty
    "reactor-netty":                    ("io.projectreactor.netty",           "reactor-netty"),
    "reactor-netty-core":               ("io.projectreactor.netty",           "reactor-netty-core"),
    "reactor-netty-http":               ("io.projectreactor.netty",           "reactor-netty-http"),
    "reactor-netty-incubator-quic":     ("io.projectreactor.netty.incubator", "reactor-netty-incubator-quic"),
    # Protobuf
    "protobuf-java":                    ("com.google.protobuf",               "protobuf-java"),
    "protobuf-java-util":               ("com.google.protobuf",               "protobuf-java-util"),
    # Spring AMQP
    "spring-amqp":                      ("org.springframework.amqp",          "spring-amqp"),
    "spring-rabbit":                    ("org.springframework.amqp",          "spring-rabbit"),
    # Spring Framework (commons)
    "spring-core":                      ("org.springframework",               "spring-core"),
    "spring-web":                       ("org.springframework",               "spring-web"),
    "spring-webmvc":                    ("org.springframework",               "spring-webmvc"),
    "spring-context":                   ("org.springframework",               "spring-context"),
    "spring-beans":                     ("org.springframework",               "spring-beans"),
    # Apache Commons
    "commons-collections":              ("org.apache.commons",                "commons-collections"),
    "commons-collections4":             ("org.apache.commons",                "commons-collections4"),
    "commons-io":                       ("commons-io",                        "commons-io"),
    "commons-lang3":                    ("org.apache.commons",                "commons-lang3"),
    # Log4j
    "log4j-core":                       ("org.apache.logging.log4j",          "log4j-core"),
    "log4j-api":                        ("org.apache.logging.log4j",          "log4j-api"),
    # Jackson
    "jackson-databind":                 ("com.fasterxml.jackson.core",        "jackson-databind"),
    "jackson-core":                     ("com.fasterxml.jackson.core",        "jackson-core"),
    # Netty directo
    "netty-all":                        ("io.netty",                          "netty-all"),
    "netty-buffer":                     ("io.netty",                          "netty-buffer"),
    "netty-codec":                      ("io.netty",                          "netty-codec"),
    "netty-codec-http":                 ("io.netty",                          "netty-codec-http"),
    "netty-codec-http2":                ("io.netty",                          "netty-codec-http2"),
    "netty-handler":                    ("io.netty",                          "netty-handler"),
    "netty-transport":                  ("io.netty",                          "netty-transport"),
    "netty-resolver":                   ("io.netty",                          "netty-resolver"),
    "netty-resolver-dns":               ("io.netty",                          "netty-resolver-dns"),
    # Guava
    "guava":                            ("com.google.guava",                  "guava"),
    # Bouncy Castle
    "bcprov-jdk15on":                   ("org.bouncycastle",                  "bcprov-jdk15on"),
    "bcprov-jdk18on":                   ("org.bouncycastle",                  "bcprov-jdk18on"),
    # Snakeyaml
    "snakeyaml":                        ("org.yaml",                          "snakeyaml"),
}

# Artifacts que son fat JARs conocidos (contienen otras libs shadeadas)
_KNOWN_SHADED_JARS: set[str] = {
    "grpc-netty-shaded",
}


class DepCheckIngester:
    """
    Lee el reporte JSON de OWASP Dependency-Check y retorna DepCheckFindings
    normalizados y deduplicados.

    Uso básico:
        ingester = DepCheckIngester("dependency-check-report.json")
        all_findings = ingester.load()
        gate_blockers = ingester.filter_by_cvss(all_findings, threshold=7.0)
    """

    def __init__(self, report_path: str):
        self.report_path = Path(report_path)
        if not self.report_path.exists():
            raise FileNotFoundError(f"Reporte no encontrado: {report_path}")
        self._schema_version: Optional[str] = None

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def load(self) -> list[DepCheckFinding]:
        """
        Carga y normaliza todos los findings del reporte.
        Retorna findings deduplicados por CVE (CASO 5).

        Un finding = un CVE. Si el mismo CVE aparece en N paquetes,
        retorna UN finding con N affected_packages.
        """
        with open(self.report_path, encoding="utf-8") as f:
            data = json.load(f)

        self._schema_version = data.get("reportSchema", "unknown")

        # Acumular: cve_id → DepCheckFinding (para deduplicación)
        findings_by_cve: dict[str, DepCheckFinding] = {}

        for dep in data.get("dependencies", []):
            vulns = dep.get("vulnerabilities", [])
            if not vulns:
                continue

            package = self._parse_package(dep)

            for vuln in vulns:
                cve_id = vuln.get("name", "").strip()
                if not cve_id:
                    continue

                if cve_id in findings_by_cve:
                    # CASO 5: CVE ya visto — agregar paquete a la lista
                    existing = findings_by_cve[cve_id]
                    existing_names = {p.file_name for p in existing.affected_packages}
                    if package.file_name not in existing_names:
                        existing.affected_packages.append(package)
                        existing._select_primary_package()
                else:
                    finding = self._parse_finding(cve_id, vuln, package)
                    findings_by_cve[cve_id] = finding

        return list(findings_by_cve.values())

    def filter_by_cvss(
        self,
        findings: list[DepCheckFinding],
        threshold: float = 7.0,
    ) -> list[DepCheckFinding]:
        """
        Filtra findings que superan el umbral CVSS.

        Comportamiento por caso:
        - CVSS v3 disponible: comparar directamente
        - Solo CVSS v2 (CASO 4): usar v2 score pero marcar para revisión humana
        - Sin score (CASO 6): NO incluir en gate blockers automáticamente,
          agregar a lista de requires_human_review

        Args:
            findings: Lista de DepCheckFindings (output de load())
            threshold: Score mínimo para considerar gate blocker. Default: 7.0

        Returns:
            Findings que superan el umbral, ordenados por score descendente.
        """
        blockers = []
        for f in findings:
            if f.cvss is None:
                f.requires_human_review = True
                f.identification_issues.append(
                    "Sin score CVSS — no evaluable automáticamente por umbral numérico"
                )
                continue
            if f.cvss.score >= threshold:
                if f.cvss.source == CvssSource.V2_FALLBACK:
                    # CASO 4: v2 no es directamente comparable con el gate v3
                    f.requires_human_review = True
                    f.identification_issues.append(
                        f"Score CVSS obtenido de v2 ({f.cvss.score}) — "
                        f"el gate está configurado para v3. Comparación aproximada."
                    )
                blockers.append(f)

        return sorted(blockers, key=lambda f: f.cvss.score, reverse=True)

    def get_report_metadata(self) -> dict:
        """Retorna metadata del reporte para diagnóstico."""
        with open(self.report_path, encoding="utf-8") as f:
            data = json.load(f)
        scan_info = data.get("scanInfo", {})
        project_info = data.get("projectInfo", {})
        return {
            "schema_version": data.get("reportSchema", "unknown"),
            "scanner_version": scan_info.get("engineVersion", "unknown"),
            "project_name": project_info.get("name", "unknown"),
            "report_date": project_info.get("reportDate", "unknown"),
            "total_dependencies": len(data.get("dependencies", [])),
            "dependencies_with_vulns": sum(
                1 for d in data.get("dependencies", []) if d.get("vulnerabilities")
            ),
        }

    # ------------------------------------------------------------------
    # Parsing interno
    # ------------------------------------------------------------------

    def _parse_package(self, dep: dict) -> AffectedPackage:
        """Extrae y normaliza la información de identificación del paquete."""
        raw_file_name = dep.get("fileName", "")
        raw_file_path = dep.get("filePath", "")

        # Detectar y resolver JAR anidado
        nested_match = _NESTED_JAR_RE.match(raw_file_name)
        is_nested = bool(nested_match)
        if is_nested:
            outer_jar = raw_file_name.split(":")[0].strip()
            file_name = nested_match.group(1).strip()
        else:
            outer_jar = None
            file_name = raw_file_name

        # Extraer artifact name y version del nombre del JAR
        jar_match = _JAR_NAME_RE.match(file_name)
        artifact_name = jar_match.group(1) if jar_match else file_name.replace(".jar", "")
        artifact_version = jar_match.group(2) if jar_match else "unknown"

        # Detectar si es fat JAR shadeado
        is_shaded = artifact_name in _KNOWN_SHADED_JARS

        # Extraer CPE
        cpe = self._extract_best_cpe(dep)
        cpe_version_mismatch = self._detect_cpe_version_mismatch(
            cpe, artifact_name, artifact_version
        )

        # Determinar PURL
        purl, purl_confidence, purl_source = self._resolve_purl(
            dep, artifact_name, artifact_version, is_shaded
        )

        return AffectedPackage(
            file_name=file_name,
            file_path=raw_file_path,
            is_nested=is_nested,
            outer_jar=outer_jar,
            purl=purl,
            purl_confidence=purl_confidence,
            purl_source=purl_source,
            cpe=cpe,
            cpe_version_mismatch=cpe_version_mismatch,
            shadowed_dependency=is_shaded,
            artifact_name=artifact_name,
            artifact_version=artifact_version,
        )

    def _resolve_purl(
        self,
        dep: dict,
        artifact_name: str,
        artifact_version: str,
        is_shaded: bool,
    ) -> tuple[Optional[str], PurlConfidence, str]:
        """
        Resuelve el PURL en orden de confianza descendente.

        Returns:
            (purl, confidence, source_description)
        """
        # CASO 1: PURL explícito en el reporte
        packages = dep.get("packages", [])
        if packages:
            high_conf = [p for p in packages if p.get("confidence") == "HIGH"]
            source = high_conf[0] if high_conf else packages[0]
            purl = source.get("id", "").strip()
            if purl and purl.startswith("pkg:"):
                return purl, PurlConfidence.HIGH, "report"

        # CASO 2 / 3: Reconstruir desde tabla de mappings conocidos
        if artifact_name in _KNOWN_MAVEN_ARTIFACTS:
            group_id, artifact_id = _KNOWN_MAVEN_ARTIFACTS[artifact_name]
            purl = f"pkg:maven/{group_id}/{artifact_id}@{artifact_version}"
            confidence = PurlConfidence.LOW if is_shaded else PurlConfidence.MEDIUM
            return purl, confidence, "reconstructed"

        # Sin PURL posible
        return None, PurlConfidence.UNAVAILABLE, "none"

    def _extract_best_cpe(self, dep: dict) -> Optional[str]:
        """Extrae el CPE más específico disponible."""
        vuln_ids = dep.get("vulnerabilityIds", [])
        cpes = [
            v["id"] for v in vuln_ids
            if v.get("id", "").startswith("cpe:") and v.get("confirmed") != "false"
        ]
        if not cpes:
            cpes = [v["id"] for v in vuln_ids if v.get("id", "").startswith("cpe:")]
        return cpes[0] if cpes else None

    def _detect_cpe_version_mismatch(
        self,
        cpe: Optional[str],
        artifact_name: str,
        artifact_version: str,
    ) -> bool:
        """
        Detecta CASO 2: el CPE usa la versión del JAR wrapper como versión
        del vendor, lo cual no corresponde al paquete real.

        Ejemplo: reactor-netty-1.2.9 → CPE cpe:2.3:a:netty:netty:1.2.9
        Netty real es 4.x, no 1.2.9. El CPE está mal.
        """
        if not cpe:
            return False

        # Si el artifact es un wrapper conocido de Netty y el CPE dice netty:netty,
        # la versión del CPE es la del wrapper, no la de Netty interno
        netty_wrappers = {
            "reactor-netty", "reactor-netty-core",
            "reactor-netty-http", "reactor-netty-incubator-quic",
        }
        if artifact_name in netty_wrappers and "netty:netty" in cpe:
            return True

        return False

    def _parse_finding(
        self,
        cve_id: str,
        vuln: dict,
        package: AffectedPackage,
    ) -> DepCheckFinding:
        """Construye un DepCheckFinding a partir de los datos del CVE."""
        severity = vuln.get("severity", "UNKNOWN").upper()
        description = (vuln.get("description") or "")[:500]
        cwes = vuln.get("cwes", [])

        cvss = self._parse_cvss(vuln)

        issues: list[str] = []
        needs_review = False

        if package.purl_confidence == PurlConfidence.UNAVAILABLE:
            issues.append(
                "PURL no disponible — reachability no puede ejecutarse automáticamente"
            )
            needs_review = True
        elif package.purl_confidence == PurlConfidence.LOW:
            issues.append(
                f"PURL reconstruido con baja confianza para fat JAR '{package.artifact_name}' — "
                f"verificar que la versión {package.artifact_version} corresponda al paquete real"
            )

        if package.cpe_version_mismatch:
            issues.append(
                f"CPE version mismatch: el CPE '{package.cpe}' usa la versión "
                f"del JAR wrapper ({package.artifact_version}), "
                f"no la versión real del componente interno"
            )
            needs_review = True

        if package.shadowed_dependency:
            issues.append(
                f"'{package.artifact_name}' es un fat JAR que contiene dependencias shadeadas — "
                f"la explotabilidad del CVE depende de la versión del componente interno, "
                f"no de la versión del JAR wrapper"
            )

        if cvss and cvss.source == CvssSource.V2_FALLBACK:
            issues.append(
                f"CVE antiguo — solo tiene CVSS v2 ({cvss.score}). "
                f"Comparación con threshold de gate (v3) es aproximada."
            )
            needs_review = True

        if cvss is None:
            issues.append("Sin score CVSS — no evaluable automáticamente")
            needs_review = True

        return DepCheckFinding(
            cve_id=cve_id,
            severity=severity,
            cvss=cvss,
            description=description,
            cwes=cwes,
            affected_packages=[package],
            identification_issues=issues,
            requires_human_review=needs_review,
        )

    def _parse_cvss(self, vuln: dict) -> Optional[DepCheckCvss]:
        """
        Extrae el score CVSS. Prioriza v3, hace fallback a v2.
        Retorna None si no hay score en absoluto.
        """
        # CVSS v3
        v3 = vuln.get("cvssv3")
        if v3 and v3.get("baseScore") is not None:
            return DepCheckCvss(
                score=float(v3["baseScore"]),
                source=CvssSource.V3,
                attack_vector=v3.get("attackVector"),
                privileges_required=v3.get("privilegesRequired"),
                user_interaction=v3.get("userInteraction"),
                confidentiality_impact=v3.get("confidentialityImpact"),
                integrity_impact=v3.get("integrityImpact"),
                availability_impact=v3.get("availabilityImpact"),
            )

        # CASO 4: Fallback a CVSS v2
        v2 = vuln.get("cvssv2")
        if v2 and v2.get("score") is not None:
            return DepCheckCvss(
                score=float(v2["score"]),
                source=CvssSource.V2_FALLBACK,
                attack_vector=v2.get("accessVector"),
                privileges_required=None,   # v2 usa "authentication", no "privilegesRequired"
                user_interaction=None,
            )

        # CASO 6: Sin score
        return None


# ---------------------------------------------------------------------------
# CLI de diagnóstico
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Uso: python -m zeronoise.clients.depcheck_ingester path/to/report.json [threshold]

    Imprime un diagnóstico del reporte: todos los findings, su calidad de datos
    y cuáles serían gate blockers para el threshold dado.
    """
    if len(sys.argv) < 2:
        print("Uso: python -m zeronoise.clients.depcheck_ingester <report.json> [cvss_threshold]")
        sys.exit(1)

    report_path = sys.argv[1]
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 7.0

    ingester = DepCheckIngester(report_path)
    meta = ingester.get_report_metadata()
    all_findings = ingester.load()
    blockers = ingester.filter_by_cvss(all_findings, threshold)

    print(f"\n{'='*60}")
    print(f"  DEPCHECK INGESTER — DIAGNOSTICO")
    print(f"{'='*60}")
    print(f"  Proyecto:   {meta['project_name']}")
    print(f"  Scanner:    {meta['scanner_version']}  (schema {meta['schema_version']})")
    print(f"  Fecha:      {meta['report_date']}")
    print(f"  Deps total: {meta['total_dependencies']}")
    print(f"  Con vulns:  {meta['dependencies_with_vulns']}")
    print(f"  CVEs unicos encontrados: {len(all_findings)}")
    print(f"  Gate blockers (CVSS >= {threshold}): {len(blockers)}")
    print()

    for f in all_findings:
        score_str = f"{f.cvss.score} ({f.cvss.source.value})" if f.cvss else "N/A"
        purl_str = f.effective_purl or "UNAVAILABLE"
        conf_str = f.primary_package.purl_confidence.value if f.primary_package else "N/A"
        is_blocker = f in blockers
        marker = "BLOCKER" if is_blocker else "no blocker"

        print(f"  [{marker}] {f.cve_id}  CVSS: {score_str}  {f.severity}")
        print(f"    PURL ({conf_str}): {purl_str}")
        print(f"    Paquetes afectados: {len(f.affected_packages)}")
        if f.affected_packages:
            for p in f.affected_packages:
                print(f"      - {p.file_name}")
        if f.identification_issues:
            print(f"    Issues:")
            for issue in f.identification_issues:
                print(f"      . {issue}")
        if f.requires_human_review:
            print(f"    REQUIERE REVISION HUMANA")
        print()