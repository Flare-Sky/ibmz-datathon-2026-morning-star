"""Train a three-class *triage* model for Q-Safe Crypto Auditor on IBM LinuxONE.

Labels (not security verdicts):
  0 = other / ambiguous / outside the asymmetric-or-PQC triage scope
  1 = likely classical asymmetric cryptographic API usage
  2 = likely post-quantum cryptographic API usage

Training examples are curated synthetic *call expressions*, matching the input
shape sent to the AI model by ai/audit.py. This is a small research prototype;
evaluation on synthetic holdouts is not evidence of real-world reliability.

Dependencies: scikit-learn, joblib (on LinuxONE, install using apt where practical).
Usage: /usr/bin/python3 train_model_v3.py
       /usr/bin/python3 train_model_v3.py --output ~/models/crypto_classifier_v3.joblib
"""

import argparse
import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.pipeline import FeatureUnion, Pipeline

LABELS = {
    0: "OTHER_OR_UNCLASSIFIED",
    1: "POSSIBLY_QUANTUM_VULNERABLE_ASYMMETRIC",
    2: "POSSIBLY_POST_QUANTUM_PRIMITIVE",
}

# A *positive* example here means it contains a likely relevant primitive,
# not that its complete implementation/protocol is secure or insecure.
# Examples are valid Python call expressions, but are NEVER executed.
TRAIN = {
    0: [
        "hashlib.sha256(payload).digest()",
        "hashlib.sha512(message).hexdigest()",
        "hashlib.sha384(blob).digest()",
        "hashlib.blake2b(payload).hexdigest()",
        "hashlib.shake_256(data).digest(32)",
        "hashlib.md5(data).digest()",
        "Crypto.Hash.SHA256.new(data=message)",
        "Crypto.Hash.SHA512.new(data=payload)",
        "hmac.new(key, message, 'sha256')",
        "hashlib.pbkdf2_hmac('sha256', password, salt, 100000)",
        "hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)",
        "bcrypt.hashpw(password, salt)",
        "secrets.token_bytes(32)",
        "secrets.compare_digest(a, b)",
        "AES.new(session_key, AES.MODE_ECB)",
        "AES.new(key_16_bytes, AES.MODE_CBC, iv)",
        "AES.new(key_32_bytes, AES.MODE_GCM)",
        "Cipher(algorithms.AES(key), modes.CBC(iv))",
        "Cipher(algorithms.AES(key), modes.GCM(iv))",
        "Fernet(key).encrypt(payload)",
        "AESGCM(key).encrypt(nonce, plaintext, aad)",
        "jwt.encode(payload, secret, algorithm='HS256')",
        "jwt.decode(token, secret, algorithms=['HS384'])",
        "jwt.encode(payload, secret, algorithm='HS512')",
        "ssl.create_default_context()",
        "logger.info('RSA key migration scheduled')",
        "print('ML-KEM-768 is a NIST algorithm')",
        "config.get('rsa_key_timeout')",
        "settings.get('ecdsa_feature_flag')",
        "cipher_name.lower()",
        "encrypt(payload)",
        "decrypt(ciphertext)",
        "crypto_helper.encrypt(data)",
        "crypto_helper.decrypt(blob)",
        "unknown_crypto_api(data)",
        "sign_data(message)",
        "verify_signature(message, signature)",
        "get_public_key(user_id)",
        "fetch_encryption_config('current')",
        "rsa_logger.info('connection ready')",
        "ec_utils.serialize_point(point)",
        "km.load_encryption_policy()",
    ],
    1: [
        "RSA.generate(2048)",
        "RSA.generate(bits=3072)",
        "Crypto.PublicKey.RSA.generate(1024)",
        "Crypto.PublicKey.RSA.generate(4096)",
        "Crypto.PublicKey.RSA.import_key(pem)",
        "RSA.import_key(private_pem)",
        "Crypto.PublicKey.RSA.construct(components)",
        "ECC.generate(curve='P-256')",
        "ECC.generate(curve='P-384')",
        "Crypto.PublicKey.ECC.generate(curve='P-521')",
        "Crypto.PublicKey.ECC.import_key(pem)",
        "ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)",
        "ecdsa.SigningKey.from_pem(pem)",
        "ecdsa.VerifyingKey.from_pem(public_pem)",
        "jwt.encode(payload, private_key, algorithm='RS256')",
        "jwt.encode(payload, private_key, algorithm='RS384')",
        "jwt.encode(payload, private_key, algorithm='PS256')",
        "jwt.encode(payload, ec_key, algorithm='ES256')",
        "jwt.encode(payload, ec_key, algorithm='ES384')",
        "jwt.decode(token, rsa_public_key, algorithms=['RS256'])",
        "jwt.decode(token, ec_public_key, algorithms=['ES256'])",
        "PKCS1_OAEP.new(rsa_public_key)",
        "PKCS1_v1_5.new(rsa_private_key)",
        "Crypto.Signature.pss.new(rsa_private_key)",
        "Crypto.Signature.pkcs1_15.new(rsa_key)",
        "DSA.generate(2048)",
        "Crypto.PublicKey.DSA.generate(3072)",
        "dh.generate_parameters(generator=2, key_size=2048)",
        "DH.generate_parameters(generator=2, key_size=3072)",
        "x25519.X25519PrivateKey.generate()",
        "x448.X448PrivateKey.generate()",
        "X25519PrivateKey.generate()",
        "X448PrivateKey.generate()",
        "crypto.PKey().generate_key(crypto.TYPE_RSA, 2048)",
        "rsa_private_key.decrypt(ciphertext, padding.OAEP(mgf, algorithm, None))",
        "rsa_private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())",
        "ec_private_key.sign(data, ec.ECDSA(hashes.SHA384()))",
        "ec_private_key.exchange(ec.ECDH(), peer_public_key)",
        "rsa_public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())",
        "ec_public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))",
        "Crypto.Cipher.PKCS1_OAEP.new(rsa_key)",
        "tls.configure_key_exchange('ECDHE-RSA')",
    ],
    2: [
        "oqs.KeyEncapsulation('ML-KEM-768')",
        "oqs.KeyEncapsulation('ML-KEM-512')",
        "oqs.KeyEncapsulation('Kyber768')",
        "oqs.KeyEncapsulation('Kyber512')",
        "oqs.KeyEncapsulation('Kyber1024')",
        "oqs.KeyEncapsulation('ML-KEM-768', secret_key)",
        "oqs.Signature('ML-DSA-65')",
        "oqs.Signature('ML-DSA-44')",
        "oqs.Signature('Dilithium2')",
        "oqs.Signature('Dilithium3')",
        "oqs.Signature('Dilithium5')",
        "oqs.Signature('Falcon-512')",
        "oqs.Signature('SPHINCS+-SHA2-128f-simple')",
        "oqs.Signature('SLH-DSA-SHA2-128s')",
        "oqs.Signature('SLH-DSA-SHAKE-192f')",
        "pqcrypto.kem.ml_kem_512.generate_keypair()",
        "pqcrypto.kem.ml_kem_768.generate_keypair()",
        "pqcrypto.kem.ml_kem_1024.generate_keypair()",
        "pqcrypto.kem.ml_kem_768.encrypt(message, public_key)",
        "pqcrypto.kem.ml_kem_768.decrypt(ciphertext, secret_key)",
        "pqcrypto.sign.ml_dsa_44.generate_keypair()",
        "pqcrypto.sign.ml_dsa_65.generate_keypair()",
        "pqcrypto.sign.ml_dsa_87.generate_keypair()",
        "pqcrypto.sign.ml_dsa_65.sign(message, secret_key)",
        "pqcrypto.sign.ml_dsa_65.verify(signature, message, public_key)",
        "pqcrypto.sign.ml_dsa_44.sign(payload, signing_key)",
        "pqcrypto.sign.ml_dsa_87.verify(signature, payload, public_key)",
        "pqcrypto.sign.sphincs_sha2_128f_simple.generate_keypair()",
        "liboqs.KeyEncapsulation('ML-KEM-768')",
        "liboqs.Signature('ML-DSA-65')",
        "pqc.generate_keypair('ML-KEM-512')",
        "pqc.encapsulate('ML-KEM-768', public_key)",
        "pqc.sign('ML-DSA-44', message)",
        "pqc.verify('ML-DSA-65', signature, message)",
        "kem.generate_keypair('ML-KEM-768')",
        "kem.encapsulate('ML-KEM-512', public_key)",
        "pqc_signature.sign('SLH-DSA-SHA2-128s', data)",
        "oqs.Signature('SPHINCS+-SHAKE-192s-simple')",
        "oqs.KeyEncapsulation('Classic-McEliece-348864')",
        "oqs.KeyEncapsulation('HQC-128')",
    ],
}

# Explicit, never-trained *synthetic* holdout. These examples are more than
# key-size replacements, but still share API families with training examples.
# Do not call this an external benchmark or claim validated security accuracy.
HOLDOUT = {
    0: [
        "hashlib.sha3_256(data).hexdigest()",
        "hashlib.blake2s(message).digest()",
        "hmac.new(secret, payload, digestmod='sha512').digest()",
        "AES.new(secret_key, AES.MODE_CTR, nonce=n)",
        "Cipher(algorithms.AES(k), modes.ECB())",
        "jwt.encode(claims, shared_secret, algorithm='HS512')",
        "crypto_utils.encrypt_stream(stream)",
        "config.get('ml_kem_enabled')",
        "logger.warning('ECDH keys will be rotated')",
        "secrets.token_hex(32)",
    ],
    1: [
        "RSA.generate(bits=8192)",
        "Crypto.PublicKey.ECC.generate(curve='P-224')",
        "jwt.encode(claims, signing_key, algorithm='RS512')",
        "jwt.decode(token, pubkey, algorithms=['PS512'])",
        "ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)",
        "Crypto.Signature.pss.new(server_rsa_key)",
        "x25519.X25519PrivateKey.from_private_bytes(key_bytes)",
        "ec_private_key.exchange(ec.ECDH(), remote_public_key)",
        "PKCS1_OAEP.new(server_public_key)",
        "Crypto.PublicKey.DSA.generate(2048)",
    ],
    2: [
        "oqs.KeyEncapsulation('ML-KEM-1024', secret_key)",
        "oqs.Signature('ML-DSA-87', secret_key)",
        "oqs.Signature('SLH-DSA-SHA2-256s')",
        "pqcrypto.kem.ml_kem_512.encrypt(payload, public_key)",
        "pqcrypto.sign.ml_dsa_87.sign(message, private_key)",
        "pqcrypto.sign.sphincs_shake_128f_simple.sign(data, secret_key)",
        "pqc.encapsulate('ML-KEM-1024', peer_key)",
        "liboqs.Signature('ML-DSA-87')",
        "kem.generate_keypair('ML-KEM-1024')",
        "oqs.KeyEncapsulation('HQC-256')",
    ],
}

# The following eight samples were used to diagnose v2. They are now an
# exploratory REGRESSION SET, not independent test data. A model that passes
# these tests alone is not validated.
REGRESSION = {
    0: [
        "AES.new(key_16_bytes, AES.MODE_ECB)",
        "hashlib.sha256(data).digest()",
        "print('RSA and ECC are obsolete')",
        "config = {'algorithm': 'unknown'}",
    ],
    1: [
        "RSA.generate(4096)",
        "jwt.encode(payload, key, algorithm='RS512')",
    ],
    2: [
        "oqs.KeyEncapsulation('ML-KEM-1024')",
        "oqs.Signature('ML-DSA-87')",
    ],
}


# Challenging, different API families and unsupported API calls. This is a
# deliberately difficult, manually specified stress set; it can reveal failures
# of out-of-distribution generalization and is NOT a population estimate.
STRESS = {
    0: [
        "Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)",
        "pqcrypto.kem.ml_kem_768.get_version()",
        "oqs.Signature('not-a-real-algorithm')",
        "hashlib.sha3_512(payload).digest()",
    ],
    1: [
        "nacl.signing.SigningKey.generate()",
        "ed25519.Ed25519PrivateKey.generate()",
        "nacl.public.PrivateKey.generate()",
        "ecies.encrypt(remote_public_key, plaintext)",
    ],
    2: [
        "pyspx.shake_128f.sign(message, sk)",
        "pqcrypto.sign.falcon_512.generate_keypair()",
        "kyber1024.encapsulate(public_key)",
        "dilithium5.sign(message, sk)",
    ],
}


def flatten(data):
    return [(snippet, label) for label, snippets in data.items() for snippet in snippets]


def validate_dataset(train, holdout):
    if {lab for _, lab in train} != {0, 1, 2}:
        raise ValueError("Training must include exactly three classes")
    def norm(s):
        return " ".join(s.strip().split()).casefold()
    all_seen = {}
    for partition, rows in (("train", train), ("holdout", holdout)):
        for source, label in rows:
            try:
                ast.parse(source, mode="exec")
            except SyntaxError as exc:
                raise ValueError(f"Invalid Python in {partition}: {source}") from exc
            key = norm(source)
            if key in all_seen:
                raise ValueError(
                    f"Exact duplicate in {partition}, first seen in {all_seen[key]}: {source}"
                )
            all_seen[key] = partition


def make_model():
    return Pipeline([
        ("features", FeatureUnion([
            ("word_tfidf", TfidfVectorizer(
                token_pattern=r"[a-zA-Z0-9_#-]+",
                lowercase=True,
                ngram_range=(1, 2),
                sublinear_tf=True,
            )),
            ("char_tfidf", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                sublinear_tf=True,
            )),
        ])),
        ("clf", LogisticRegression(
            C=2.0,
            max_iter=2000,
            class_weight="balanced",
            random_state=42,
        )),
    ])


def evaluate(model, rows, name):
    text = [x for x, _ in rows]
    truth = [y for _, y in rows]
    pred = [int(p) for p in model.predict(text)]
    cm = confusion_matrix(truth, pred, labels=[0, 1, 2]).tolist()
    acc = accuracy_score(truth, pred)
    print(f"\n{name}: {len(rows)} synthetic examples, accuracy={acc:.1%}")
    print("Confusion matrix (rows=true, columns=predicted; order 0,1,2):")
    for row in cm:
        print(" ", row)
    print(classification_report(
        truth, pred, labels=[0, 1, 2],
        target_names=[LABELS[i] for i in range(3)], zero_division=0,
    ))
    errors = []
    probabilities = model.predict_proba(text)
    for (snippet, y), p, probs in zip(rows, pred, probabilities):
        if y != p:
            confidence = float(max(probs))
            print(f"  WRONG {y}->{p} ({confidence:.1%}): {snippet}")
            errors.append({"expected": y, "predicted": p, "probability": round(confidence, 4), "code": snippet})
    return {"count": len(rows), "accuracy": round(float(acc), 4), "confusion_matrix": cm, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="~/models/crypto_classifier_v3.joblib",
        help="Destination model; refuses to overwrite an existing artifact",
    )
    parser.add_argument(
        "--report", default="~/models/crypto_classifier_v3_evaluation.json",
        help="Destination JSON evaluation report",
    )
    args = parser.parse_args()
    output = Path(args.output).expanduser()
    report_path = Path(args.report).expanduser()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite existing model: {output}")

    train = flatten(TRAIN)
    holdout = flatten(HOLDOUT)
    validate_dataset(train, holdout)
    # Also avoid exact leakage from earlier v2 diagnostic cases.
    train_keys = {" ".join(s.split()).casefold() for s, _ in train}
    test_keys = {" ".join(s.split()).casefold() for s, _ in holdout}
    regression_keys = {" ".join(s.split()).casefold() for s, _ in flatten(REGRESSION)}
    if regression_keys & (train_keys | test_keys):
        raise ValueError("Exact regression snippet overlaps train/holdout")
    X_train = [x for x, _ in train]
    y_train = [y for _, y in train]
    print("Training counts:", dict(sorted(Counter(y_train).items())))
    print("Synthetic holdout counts:", dict(sorted(Counter(y for _, y in holdout).items())))
    model = make_model()
    model.fit(X_train, y_train)
    if list(model.classes_) != [0, 1, 2]:
        raise RuntimeError("Wrong classes for LinuxONE auditor")

    holdout_results = evaluate(model, holdout, "SYNTHETIC HOLDOUT")
    regression_results = evaluate(model, flatten(REGRESSION), "V2 DEVELOPMENT REGRESSION")
    stress_results = evaluate(model, flatten(STRESS), "OUT-OF-FAMILY SYNTHETIC STRESS")
    dataset_hash = sha256(json.dumps(train, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    report = {
        "disclaimer": "Small synthetic datasets. Not calibrated probabilities or real-world security accuracy.",
        "labels": LABELS,
        "train_counts": dict(Counter(y_train)),
        "holdout_counts": dict(Counter(y for _, y in holdout)),
        "training_data_sha256": dataset_hash,
        "synthetic_holdout": holdout_results,
        "v2_development_regression": regression_results,
        "out_of_family_synthetic_stress": stress_results,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output)
    print(f"\nWrote model: {output}")
    print(f"Wrote evaluation: {report_path}")
    print("No API service or production model was changed.")


if __name__ == "__main__":
    main()
