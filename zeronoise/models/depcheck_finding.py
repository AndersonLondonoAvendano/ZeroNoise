"""
depcheck_finding.py — Modelo de datos para findings de OWASP Dependency-Check.

Diseñado para ser tolerante a los diferentes estados del reporte JSON:
- PURL presente o ausente
- CVSS v3 presente o solo v2
- CPE con versión correcta o con mismatch
- JARs directos o anidados en fat JARs
- Mismo CVE reportado en múltiples JARs

Este modelo es PARALELO a Finding de models/vulnerability.py — no lo reemplaza.
Finding representa un finding de Dependency-Track (con UUID, estado de análisis, etc).
DepCheckFinding representa un finding del reporte estático de dep-check (sin UUIDs de DT).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PurlConfidence(str, Enum):
    """Confianza en el PURL utilizado para reachability."""
    HIGH        = "HIGH"         # PURL explícito del reporte
    MEDIUM      = "MEDIUM"       # Reconstruido desde artifact name conocido
    LOW         = "LOW"          # Reconstruido con heurística, posible error
    UNAVAILABLE = "UNAVAILABLE"  # No fue posible determinar un PURL


class CvssSource(str, Enum):
    """Origen del score CVSS usado para la evaluación."""
    V3          = "v3"           # CVSS v3 presente en el reporte
    V2_FALLBACK = "v2_fallback"  # Solo CVSS v2 disponible (CVE antiguo)
    UNAVAILABLE = "unavailable"  # Sin score numérico


@dataclass
class DepCheckCvss:
    """Score CVSS normalizado — puede venir de v3 o v2."""
    score: float
    source: CvssSource
    attack_vector: Optional[str] = None         # NETWORK | ADJACENT | LOCAL | PHYSICAL
    privileges_required: Optional[str] = None   # NONE | LOW | HIGH
    user_interaction: Optional[str] = None      # NONE | REQUIRED
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None

    def exceeds_threshold(self, threshold: float = 7.0) -> bool:
        return self.score >= threshold


@dataclass
class AffectedPackage:
    """
    Un paquete donde dep-check detectó el CVE.
    Un mismo CVE puede aparecer en múltiples paquetes (ver CASO 5).
    """
    file_name: str               # JAR interno: "netty-resolver-dns-4.1.128.Final.jar"
    file_path: str               # Ruta completa en el workspace del runner
    is_nested: bool              # True si es JAR dentro de fat JAR
    outer_jar: Optional[str]     # Nombre del fat JAR contenedor, si aplica

    # Identificación — en orden de confianza descendente
    purl: Optional[str]                    = None                   # pkg:maven/... — puede ser None
    purl_confidence: PurlConfidence        = PurlConfidence.UNAVAILABLE
    purl_source: str                       = ""                     # "report" | "reconstructed" | "none"

    cpe: Optional[str]                     = None                   # cpe:2.3:a:... — puede estar mal mapeado
    cpe_version_mismatch: bool             = False                  # True si la versión del CPE no corresponde al paquete real
    shadowed_dependency: bool              = False                  # True si es un fat JAR con dep interna shadeada

    artifact_name: str                     = ""                     # "netty-resolver-dns" — extraído del fileName
    artifact_version: str                  = ""                     # "4.1.128.Final" — extraído del fileName


@dataclass
class DepCheckFinding:
    """
    Finding normalizado de OWASP Dependency-Check, deduplicado por CVE.

    Un DepCheckFinding representa UN CVE que puede afectar a UNO O MÁS paquetes
    del proyecto (ver CASO 5 — mismo CVE en múltiples JARs wrapper de Netty).

    Campos de diagnóstico:
    - identification_issues: lista de problemas encontrados durante el parsing
    - requires_human_review: True si algún dato es poco confiable

    Relación con Finding (models/vulnerability.py):
    - DepCheckFinding NO tiene UUIDs de DT — viene del reporte estático
    - Finding SÍ tiene UUIDs de DT — viene de la API de Dependency-Track
    - Son complementarios: DepCheckFinding es la entrada del fast-gate,
      Finding es la entrada del análisis background post SEND-SBOM
    """
    cve_id: str                             # "CVE-2026-33871"
    severity: str                           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cvss: Optional[DepCheckCvss]            # None si no hay score en absoluto
    description: str                        # Truncado a 500 chars para eficiencia de tokens
    cwes: list[str]                         = field(default_factory=list)  # ["CWE-770"]

    # Paquetes donde se detectó este CVE (deduplicados)
    affected_packages: list[AffectedPackage] = field(default_factory=list)

    # Diagnóstico de calidad del dato
    identification_issues: list[str]        = field(default_factory=list)
    requires_human_review: bool             = False

    # El paquete "principal" para reachability — el de mayor confianza de PURL
    # Se selecciona automáticamente en post_init
    primary_package: Optional[AffectedPackage] = field(default=None, init=False)

    def __post_init__(self):
        self._select_primary_package()

    def _select_primary_package(self):
        """Selecciona el paquete con mayor confianza de PURL para reachability."""
        if not self.affected_packages:
            return
        priority = {
            PurlConfidence.HIGH: 3,
            PurlConfidence.MEDIUM: 2,
            PurlConfidence.LOW: 1,
            PurlConfidence.UNAVAILABLE: 0,
        }
        self.primary_package = max(
            self.affected_packages,
            key=lambda p: priority.get(p.purl_confidence, 0),
        )

    @property
    def effective_purl(self) -> Optional[str]:
        """PURL a usar para Stage 2. Puede ser None si no hay ninguno disponible."""
        if self.primary_package:
            return self.primary_package.purl
        return None

    @property
    def can_run_reachability(self) -> bool:
        """¿Stage 2 puede ejecutarse? Requiere al menos un PURL con confianza >= MEDIUM."""
        if not self.primary_package:
            return False
        return self.primary_package.purl_confidence in (
            PurlConfidence.HIGH, PurlConfidence.MEDIUM
        )

    def exceeds_cvss_threshold(self, threshold: float = 7.0) -> bool:
        """¿Este finding supera el umbral del gate?"""
        if self.cvss is None:
            return False
        return self.cvss.score >= threshold

    @property
    def finding_id(self) -> str:
        pkg = self.effective_purl or (
            self.primary_package.artifact_name if self.primary_package else "unknown"
        )
        return f"depcheck:{self.cve_id}:{pkg}"