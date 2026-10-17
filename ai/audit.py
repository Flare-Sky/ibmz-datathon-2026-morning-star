"""Join deterministic scanner findings with non-authoritative ML suggestions."""
from scanner.detect import scan_python


def analyze_report(scan_result: dict, model) -> dict:
    suggestions = []
    positive_index = list(model.classes_).index(1)

    for candidate in scan_result.get("candidates", []):
        probability = float(
            model.predict_proba([candidate["code"]])[0][positive_index]
        )
        suggestions.append({
            **candidate,
            "ai_label": (
                "possibly_crypto_usage" if probability >= 0.5
                else "possibly_not_crypto_usage"
            ),
            "ai_probability_class_1": round(probability, 4),
            "needs_human_review": True,
        })

    findings = scan_result.get("findings", [])
    return {
        "findings": findings,
        "ai_candidates": suggestions,
        "summary": {
            "rule_findings": len(findings),
            "ai_candidates_for_review": len(suggestions),
        },
    }


def audit_source(source: str, filename: str, model) -> dict:
    return analyze_report(scan_python(source, filename), model)


def audit_project(root, model) -> dict:
    """Audit a directory using your optional Phase 4 project scanner."""
    from scanner.project import scan_project
    return analyze_report(scan_project(root), model)
