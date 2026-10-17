"""Combine AST findings with non-authoritative three-class ML suggestions."""
from scanner.detect import scan_python

AI_LABELS = {
    0: "possibly_non_crypto_or_comment",
    1: "possibly_quantum_vulnerable",
    2: "possibly_quantum_resistant",
}


def analyze_report(scan_result: dict, model) -> dict:
    classes = [int(c) for c in model.classes_]
    if set(classes) != {0, 1, 2} or len(classes) != 3:
        raise ValueError(
            "This audit requires a three-class model with labels 0, 1, 2. "
            "Use --model /home/linux1/models/crypto_classifier_v2.joblib"
        )

    suggestions = []
    for candidate in scan_result.get("candidates", []):
        probabilities = model.predict_proba([candidate["code"]])[0]
        best_idx = max(range(len(classes)), key=lambda i: float(probabilities[i]))
        chosen_class = classes[best_idx]
        suggestions.append({
            **candidate,
            "ai_class": chosen_class,
            "ai_label": AI_LABELS[chosen_class],
            "ai_probability": round(float(probabilities[best_idx]), 4),
            "ai_probabilities": {
                str(c): round(float(probabilities[i]), 4)
                for i, c in enumerate(classes)
            },
            # Predictions are not verified evidence of security or insecurity.
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
    """Audit a directory using the optional project scanner."""
    from scanner.project import scan_project
    return analyze_report(scan_project(root), model)
