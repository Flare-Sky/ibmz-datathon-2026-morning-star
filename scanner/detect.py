"""AST-based prototype cryptographic call scanner (Python >= 3.9).

Known calls are rule matches; unknown crypto-looking calls are AI-review
candidates, not confirmed vulnerabilities.
"""
import ast
import re

RULES = {
    "rsa.generate_private_key": ("RSA", "unknown", "vulnerable"),
    "ec.generate_private_key": ("ECC", "unknown", "vulnerable"),
    "ec.ECDSA": ("ECDSA", "digital_signature", "vulnerable"),
    "ec.ECDH": ("ECDH", "key_establishment", "vulnerable"),
    "AESGCM": ("AES-GCM", "symmetric_encryption", "review"),
}

PREFIX = "cryptography.hazmat.primitives"
QUALIFIED = {
    f"{PREFIX}.asymmetric.rsa.generate_private_key": RULES["rsa.generate_private_key"],
    f"{PREFIX}.asymmetric.ec.generate_private_key": RULES["ec.generate_private_key"],
    f"{PREFIX}.asymmetric.ec.ECDSA": RULES["ec.ECDSA"],
    f"{PREFIX}.asymmetric.ec.ECDH": RULES["ec.ECDH"],
    f"{PREFIX}.ciphers.aead.AESGCM": RULES["AESGCM"],
}

# Only discover *potential* API calls here. The model must never promote a
# candidate to a confirmed security finding without independent verification.
CRYPTO_CALL_HINT = re.compile(
    r"rsa|aes|ecc|ecdsa|ecdh|oqs|kem|dsa|cipher|crypt|encrypt|decrypt|sign|keyencapsulation",
    re.IGNORECASE,
)


def scan_python(source: str, filename: str) -> dict:
    tree = ast.parse(source, filename=filename)
    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            for imported in node.names:
                if imported.name != "*":
                    aliases[imported.asname or imported.name] = (
                        f"{node.module}.{imported.name}"
                    )
        elif isinstance(node, ast.Import):
            for imported in node.names:
                if imported.asname:
                    aliases[imported.asname] = imported.name

    findings, candidates = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        root, sep, rest = name.partition(".")
        normalized = aliases.get(root, root) + (sep + rest if sep else "")

        if normalized in QUALIFIED:
            algorithm, usage, status = QUALIFIED[normalized]
            confidence = "high"
        elif normalized in RULES:
            # Unqualified snippets are a name match only: not library-verified.
            algorithm, usage, status = RULES[normalized]
            confidence = "low"
        else:
            if CRYPTO_CALL_HINT.search(name):
                snippet = ast.get_source_segment(source, node) or ast.unparse(node)
                candidates.append({
                    "file": filename,
                    "line": node.lineno,
                    "evidence": name,
                    "code": " ".join(snippet.split())[:500],
                    "reason": "unrecognized_crypto_like_call",
                })
            continue

        finding = {
            "file": filename,
            "line": node.lineno,
            "algorithm": algorithm,
            "usage": usage,
            "quantum_status": status,
            "evidence": name,
            "confidence": confidence,
        }
        for keyword in node.keywords:
            if (
                keyword.arg == "key_size"
                and isinstance(keyword.value, ast.Constant)
                and type(keyword.value.value) is int
            ):
                finding["key_size"] = keyword.value.value
        findings.append(finding)

    return {"findings": findings, "candidates": candidates}
