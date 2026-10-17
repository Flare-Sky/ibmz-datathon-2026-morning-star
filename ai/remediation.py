"""Explainable migration planning for Morning Star.

Rules yield *review plans*, not security guarantees or automatically applicable
code patches. Model predictions are never promoted into verified findings.
No uploaded code is executed or transmitted to an external LLM.
"""

from typing import Any, Dict, List, Tuple


PLAYBOOKS = {
    "RSA": {
        "why": "RSA public-key cryptography is vulnerable to a sufficiently capable quantum computer.",
        "action": "Trace whether the RSA key is used for key establishment, encryption, or signing before selecting a replacement.",
        "steps": [
            "Inventory RSA key usage, protocol endpoints, libraries, certificates, and data-retention needs.",
            "For key establishment, evaluate standardized ML-KEM integration in the relevant protocol; for signatures, evaluate ML-DSA or SLH-DSA.",
            "Pilot interoperability and migration/rollback procedures before retiring legacy keys.",
        ],
        "effort": "Medium–High",
    },
    "ECC": {
        "why": "Conventional elliptic-curve public-key cryptography is quantum-vulnerable.",
        "action": "Identify whether these EC keys are used for key agreement or digital signatures.",
        "steps": [
            "Inventory curve selection, endpoints, key lifecycle and dependent protocols.",
            "Evaluate standardized ML-KEM for key establishment or ML-DSA/SLH-DSA for signatures, according to usage.",
            "Pilot protocol and library compatibility, including any supported hybrid transition.",
        ],
        "effort": "Medium–High",
    },
    "ECDH": {
        "why": "ECDH key agreement is vulnerable to sufficiently capable quantum attacks.",
        "action": "Plan a migration of the key-establishment protocol, evaluating ML-KEM and protocol-compatible hybrid options.",
        "steps": [
            "Find ECDH handshake endpoints, negotiated protocols and downstream key consumers.",
            "Verify ML-KEM support and interoperability on both sides of each connection.",
            "Pilot and roll out with fallback, monitoring and a key-transition plan.",
        ],
        "effort": "High",
    },
    "ECDSA": {
        "why": "ECDSA signatures are vulnerable to sufficiently capable quantum attacks.",
        "action": "Evaluate ML-DSA or SLH-DSA signatures with the receiving/verification ecosystem.",
        "steps": [
            "Inventory signers, verifiers, certificate requirements and signature formats.",
            "Test signature size, performance, verification compatibility and trust-chain changes.",
            "Phase in compatible post-quantum signatures and retire legacy signing dependencies.",
        ],
        "effort": "High",
    },
    "AES-GCM": {
        "why": "AES-GCM is a symmetric authenticated-encryption mode, not a Shor-vulnerable public-key scheme.",
        "action": "Review actual key length, nonce uniqueness, authentication-tag checking and key management; do not replace AES-GCM with ML-KEM.",
        "steps": [
            "Verify effective AES key length and where keys originate.",
            "Check GCM nonce uniqueness, authentication-tag validation and rotation policy.",
            "Review surrounding key-establishment dependencies separately for post-quantum migration.",
        ],
        "effort": "Low–Medium",
    },
}

ROADMAP = [
    {
        "phase": "Now — Inventory & validate",
        "effort": "Low",
        "actions": [
            "Confirm API matches and inspect unknown ML candidates before treating them as findings.",
            "Map public-key usage, sensitive data retention, affected services and library dependencies.",
            "Assign an owner to each migration candidate.",
        ],
    },
    {
        "phase": "Next — Pilot & budget",
        "effort": "Medium",
        "actions": [
            "Prioritize long-lived sensitive data and externally exposed protocols using verified business context.",
            "Evaluate standardized ML-KEM for key establishment and ML-DSA/SLH-DSA for signatures.",
            "Estimate compatibility, engineering time, vendor support and testing costs before committing funds.",
        ],
    },
    {
        "phase": "Later — Roll out & monitor",
        "effort": "Medium–High",
        "actions": [
            "Stage changes in development and production with rollback plans.",
            "Retest cross-system compatibility, crypto configuration and certificate/key lifecycles.",
            "Re-scan code and update migration evidence for internal and external reviews.",
        ],
    },
]


def build_remediation(findings: List[Dict[str, Any]],
                      candidates: List[Dict[str, Any]]) -> Tuple[List[dict], List[dict]]:
    """Return transparent, review-only recommendations and a qualitative roadmap."""
    recommendations = []
    for finding in findings:
        algorithm = str(finding.get("algorithm", "Unknown"))
        playbook = PLAYBOOKS.get(algorithm)
        confidence = finding.get("confidence")
        vulnerable = finding.get("quantum_status") == "vulnerable"
        # Low-confidence string matches cannot justify automatic high priority.
        priority = "High" if vulnerable and confidence == "high" else "Review"
        if playbook:
            why = playbook["why"]
            action = playbook["action"]
            steps = playbook["steps"]
            effort = playbook["effort"]
        else:
            why = "A recognized rule found a cryptographic API call, but its usage requires review."
            action = "Verify the algorithm and actual protocol usage before planning a change."
            steps = ["Confirm the implementation and its security requirements."]
            effort = "Unknown"
        if confidence != "high":
            action = "First verify the unqualified API match and imported library. " + action
        recommendations.append({
            "source_type": "rule_finding",
            "file": finding.get("file", ""),
            "line": finding.get("line"),
            "evidence": finding.get("evidence", ""),
            "algorithm": algorithm,
            "priority": priority,
            "effort": effort,
            "why": why,
            "recommended_action": action,
            "next_steps": steps,
            "needs_human_review": True,
        })

    for candidate in candidates:
        predicted = candidate.get("ai_class")
        if predicted == 1:
            why = "The ML model suspects a quantum-vulnerable asymmetric cryptographic call; the API has not been verified."
            action = "Validate the library, algorithm and actual use; if confirmed, select a matching key-establishment or signature migration playbook."
        elif predicted == 2:
            why = "The ML model suspects a post-quantum primitive; prediction does not prove the algorithm name or implementation is valid."
            action = "Check library documentation, actual supported algorithm identifier, parameter set and standards alignment; do not mark as verified safe."
        else:
            why = "The call was not recognized by the rule scanner, and ML evidence is inconclusive or out of scope."
            action = "Determine whether this is actually security-relevant before planning any migration."
        recommendations.append({
            "source_type": "ai_candidate",
            "file": candidate.get("file", ""),
            "line": candidate.get("line"),
            "evidence": candidate.get("evidence", ""),
            "algorithm": "Unverified API",
            "priority": "Review",
            "effort": "Low (initial verification)",
            "why": why,
            "recommended_action": action,
            "next_steps": [
                "Inspect the actual imported library and code context.",
                "Use a verified algorithm-specific migration plan only after confirmation.",
            ],
            "needs_human_review": True,
        })

    recommendations.sort(key=lambda rec: (
        0 if rec["priority"] == "High" else 1,
        str(rec["file"]),
        rec["line"] if isinstance(rec["line"], int) else 10**9,
    ))
    return recommendations, [dict(stage) for stage in ROADMAP]
