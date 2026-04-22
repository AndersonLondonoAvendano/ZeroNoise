"""
Decision tools — generate structured verdicts and VEX reports.

These tools close the Stage 2 → Stage 3 loop by producing machine-readable
outputs that CI/CD systems and vulnerability managers can consume.

Tool contracts:
  generate_finding_verdict   read_only: true  | side_effects: none          | cost: low  | heuristic
  generate_vex_report        read_only: false | side_effects: external_write | cost: low  | deterministic
"""

from datetime import datetime, timezone

from zeronoise.audit import audit_tool
from zeronoise.config import settings
from zeronoise.models.vulnerability import AnalysisJustification, VerdictTaxonomy


# Maps Stage 2 verdict strings to VEX status values (OpenVEX compatible)
_VEX_STATUS_MAP: dict[str, str] = {
    VerdictTaxonomy.NOT_REACHABLE: "not_affected",
    VerdictTaxonomy.REACHABLE: "under_investigation",
    VerdictTaxonomy.LIKELY_EXPLOITABLE: "affected",
    VerdictTaxonomy.EXPLOITABLE: "affected",
    VerdictTaxonomy.FALSE_POSITIVE: "not_affected",
    VerdictTaxonomy.NOT_APPLICABLE: "not_affected",
    VerdictTaxonomy.UNKNOWN: "under_investigation",
}

# Maps VerdictTaxonomy → DT AnalysisState for write-back
_DT_STATE_MAP: dict[str, str] = {
    VerdictTaxonomy.NOT_REACHABLE: "NOT_AFFECTED",
    VerdictTaxonomy.FALSE_POSITIVE: "FALSE_POSITIVE",
    VerdictTaxonomy.NOT_APPLICABLE: "NOT_AFFECTED",
    VerdictTaxonomy.EXPLOITABLE: "EXPLOITABLE",
    VerdictTaxonomy.LIKELY_EXPLOITABLE: "IN_TRIAGE",
    VerdictTaxonomy.REACHABLE: "IN_TRIAGE",
    VerdictTaxonomy.UNKNOWN: "NOT_SET",
}


def _check_stage3_gate(
    verdict: str,
    evidence: list[dict],
    confidence: float,
    threshold: float,
) -> dict:
    """
    Evaluate whether Stage 3 LLM analysis is allowed for this finding.

    Stage 3 MUST NOT run unless:
      1. verdict is REACHABLE or UNKNOWN
      2. evidence is non-empty
      3. confidence >= threshold
    """
    if verdict not in {VerdictTaxonomy.REACHABLE, VerdictTaxonomy.UNKNOWN}:
        return {
            "stage3_allowed": False,
            "reason": f"Verdict '{verdict}' does not require contextual analysis",
        }
    if not evidence:
        return {
            "stage3_allowed": False,
            "reason": "No evidence available — cannot justify Stage 3 token consumption",
        }
    if confidence < threshold:
        return {
            "stage3_allowed": False,
            "reason": (
                f"Confidence {confidence:.2f} is below the required threshold {threshold:.2f} — "
                "human review recommended instead"
            ),
        }
    return {
        "stage3_allowed": True,
        "reason": (
            f"Reachable with {len(evidence)} evidence item(s) at "
            f"confidence {confidence:.2f} (threshold {threshold:.2f})"
        ),
    }


@audit_tool(side_effects="none")
async def generate_finding_verdict(
    finding_id: str,
    verdict: str,
    justification: str,
    confidence: float,
    evidence: list[dict],
    analysis_details: str = "",
) -> dict:
    """
    Produce a canonical structured verdict for a single finding.

    This is the authoritative decision record — it contains the verdict,
    the evidence that supports it, and the Stage 3 gate evaluation.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: heuristic

    Args:
        finding_id: Canonical ID in the format "{component_uuid}:{vuln_uuid}".
        verdict: One of the VerdictTaxonomy values.
        justification: One of the AnalysisJustification values.
        confidence: Float 0.0–1.0 representing analysis confidence.
        evidence: List of evidence dicts (file, line, statement, matched_pattern, reason).
        analysis_details: Free-form text for the DT audit trail.
    """
    allowed_verdicts = [v.value for v in VerdictTaxonomy]
    if verdict not in allowed_verdicts:
        return {"error": f"Invalid verdict '{verdict}'. Must be one of: {allowed_verdicts}"}

    allowed_justifications = [j.value for j in AnalysisJustification]
    if justification not in allowed_justifications:
        return {
            "error": f"Invalid justification '{justification}'. Must be one of: {allowed_justifications}"
        }

    threshold = settings.stage3_confidence_threshold
    stage3_gate = _check_stage3_gate(verdict, evidence, confidence, threshold)

    return {
        "finding_id": finding_id,
        "verdict": verdict,
        "justification": justification,
        "confidence": confidence,
        "evidence": evidence,
        "analysis_details": analysis_details,
        "dt_analysis_state": _DT_STATE_MAP.get(verdict, "NOT_SET"),
        "stage3_gate": stage3_gate,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@audit_tool(side_effects="none")
async def generate_vex_report(
    project_name: str,
    project_version: str,
    findings: list[dict],
) -> dict:
    """
    Generate a VEX (Vulnerability Exploitability eXchange) report.

    The output follows the OpenVEX schema structure and can be embedded
    in CI/CD pipelines to justify security gate decisions without manual review.

    Contract:
        read_only: true
        side_effects: none
        requires_confirmation: false
        expected_cost: low
        determinism: deterministic

    Args:
        project_name: Name of the audited project.
        project_version: Version string of the project.
        findings: List of finding dicts, each containing at minimum:
                  vuln_id, purl, verdict, justification, analysis_details,
                  confidence.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    statements = []
    for f in findings:
        verdict = f.get("verdict", VerdictTaxonomy.UNKNOWN)
        vex_status = _VEX_STATUS_MAP.get(verdict, "under_investigation")
        statement = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{f.get('vuln_id', 'UNKNOWN')}",
                "name": f.get("vuln_id", "UNKNOWN"),
            },
            "products": [
                {
                    "@id": f.get("purl", f"{project_name}@{project_version}"),
                    "name": f.get("component", project_name),
                }
            ],
            "status": vex_status,
            "justification": f.get("justification", AnalysisJustification.NOT_SET),
            "impact_statement": f.get("analysis_details", ""),
            "action_statement": (
                "No action required — package not reachable from application code."
                if vex_status == "not_affected"
                else "Investigate and remediate before deployment."
            ),
            "confidence": f.get("confidence", 0.0),
            "evidence_count": len(f.get("evidence", [])),
        }
        statements.append(statement)

    exploitable = [s for s in statements if s["status"] == "affected"]
    not_affected = [s for s in statements if s["status"] == "not_affected"]
    under_investigation = [s for s in statements if s["status"] == "under_investigation"]

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "id": f"zeronoise-vex-{project_name}-{project_version}-{timestamp[:10]}",
        "author": "ZeroNoise",
        "timestamp": timestamp,
        "version": 1,
        "tooling": "ZeroNoise MCP Auditor",
        "project": {"name": project_name, "version": project_version},
        "summary": {
            "total": len(statements),
            "affected": len(exploitable),
            "not_affected": len(not_affected),
            "under_investigation": len(under_investigation),
        },
        "pipeline_decision": "BLOCK" if exploitable else "PROMOTE",
        "statements": statements,
    }
