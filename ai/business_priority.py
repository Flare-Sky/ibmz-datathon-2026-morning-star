
"""Business-context planning heuristics for reviewed cryptographic evidence.

Only verified import rule matches can receive a P1 migration-planning tier.
An ML prediction is *never* a verified vulnerability or safe-crypto finding.
Scores and windows are illustrative planning inputs, not calibrated risk,
regulatory deadlines, or estimates of actual migration cost.
"""

from typing import Any, Dict, List, Tuple
from ai.remediation import build_remediation

SENSITIVITY_WEIGHT = {"Low": 10, "Medium": 25, "High": 40}
CRITICALITY_WEIGHT = {"Low": 5, "Medium": 15, "High": 25}
COMPLEXITY_WEIGHT = {"Low": 5, "Medium": 10, "High": 15}


def business_exposure(context: Dict[str, Any]) -> float:
    """A transparent business-context heuristic; not the Mosca equation."""
    years = max(0, min(30, int(context.get("retention_years", 10))))
    sensitivity = context.get("sensitivity", "Medium")
    criticality = context.get("criticality", "Medium")
    complexity = context.get("complexity", "Medium")
    return (
        min(years * 1.4, 28.0)
        + SENSITIVITY_WEIGHT.get(sensitivity, 25) * 0.35
        + CRITICALITY_WEIGHT.get(criticality, 15) * 0.30
        + COMPLEXITY_WEIGHT.get(complexity, 10) * 0.25
    )


def build_migration_plan(
    findings: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    business_context: Dict[str, Any],
) -> Tuple[List[dict], List[dict], List[dict]]:
    """Return (priority rows, curated recommendations, staged roadmap)."""
    recommendations, roadmap = build_remediation(findings, candidates)
    exposure = business_exposure(business_context)

    lookup = {}
    for advice in recommendations:
        key = (
            advice["source_type"],
            advice.get("file"),
            advice.get("line"),
            advice.get("evidence"),
        )
        lookup[key] = advice

    rows = []
    for finding in findings:
        verified = finding.get("confidence") == "high"
        vulnerable = finding.get("quantum_status") == "vulnerable"
        if verified and vulnerable:
            score = min(99, round(46 + exposure))
            if score >= 80:
                tier, window = "P1 — Review & plan first", "Illustrative: 0–3 months"
            elif score >= 60:
                tier, window = "P2 — Near-term planning", "Illustrative: 3–12 months"
            else:
                tier, window = "P3 — Scheduled planning", "Illustrative: 12–24 months"
            tier_rank = 0
            verification = "Confirmed known-library API pattern; review actual usage"
        else:
            score = min(59, round(25 + exposure * 0.6))
            tier = "VERIFY — Rule match / configuration"
            window = "Validate API and configuration first"
            tier_rank = 1
            verification = (
                "Rule name match only" if not verified
                else "Symmetric configuration review"
            )

        key = ("rule_finding", finding.get("file"), finding.get("line"), finding.get("evidence"))
        advice = lookup.get(key, {})
        rows.append({
            "Priority Tier": tier,
            "Planning Score": score,
            "Target Window": window,
            "Line": finding.get("line"),
            "File": finding.get("file", ""),
            "Detected Artifact": (
                f"{finding.get('algorithm', 'Unknown')}-{finding['key_size']}"
                if finding.get("key_size") is not None
                else finding.get("algorithm", "Unknown")
            ),
            "Usage": finding.get("usage", "unknown"),
            "Source": "Rule Engine",
            "Verification Basis": verification,
            "Suggested Next Step": advice.get(
                "recommended_action", "Verify API use and context before migration."
            ),
            "Code Evidence": finding.get("evidence", ""),
            "_tier_rank": tier_rank,
        })

    for candidate in candidates:
        # An AI class-1 prediction must NOT be treated as a confirmed
        # vulnerability; class-2 must NOT be treated as 'safe'.
        score = min(59, round(20 + exposure * 0.6))
        key = ("ai_candidate", candidate.get("file"), candidate.get("line"), candidate.get("evidence"))
        advice = lookup.get(key, {})
        rows.append({
            "Priority Tier": "VERIFY — AI suggestion",
            "Planning Score": score,
            "Target Window": "Confirm library and algorithm first",
            "Line": candidate.get("line"),
            "File": candidate.get("file", ""),
            "Detected Artifact": f"AI class {candidate.get('ai_class', '?')} (unverified)",
            "Usage": "unknown",
            "Source": "LinuxONE ML classification",
            "Verification Basis": "Unverified model prediction",
            "Suggested Next Step": advice.get(
                "recommended_action",
                "Verify algorithm and actual usage before proposing migration.",
            ),
            "Code Evidence": candidate.get("evidence", ""),
            "_tier_rank": 2,
        })

    rows.sort(key=lambda x: (x["_tier_rank"], -x["Planning Score"], str(x["File"]), str(x["Line"])))
    for row in rows:
        row.pop("_tier_rank")
    return rows, recommendations, roadmap
