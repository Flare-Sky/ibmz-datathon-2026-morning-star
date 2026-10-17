import os
import joblib
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
# 0 = Non-crypto / Comment / Safe boilerplate
# 1 = Quantum-Vulnerable Crypto (RSA, ECC, ECDH, ECDSA, legacy DH)
# 2 = Quantum-Safe / PQC Ready (AES-256, ML-KEM, Kyber, ML-DSA, Dilithium, SHA-384/512)
train_data = [
    # --- Class 0: Non-crypto or Comments (False Positive traps) ---
    ("print('Hello World')", 0),
    ("# TODO: migrate RSA to post-quantum before 2027", 0),
    ("# Legacy ECDSA keys should be deprecated", 0),
    ("logger.info('Starting student records service on port 8080')", 0),
    ("def calculate_tuition_discount(rsa_score, student_id):", 0),
    ("import os, sys, json, datetime", 0),
    ("db.execute('SELECT * FROM users WHERE status = 1')", 0),
    ("// Note: do not use RSA-1024 in production", 0),
    ("response = requests.get('https://api.school.edu/health')", 0),
    ("config = {'timeout': 2048, 'retries': 3}", 0),
    # --- Class 1: Quantum-Vulnerable (Shor's algorithm targets) ---
    ("rsa.generate_private_key(public_exponent=65537, key_size=2048)", 1),
    ("RSA.generate(2048)", 1),
    ("RSA.generate(1024)", 1),
    ("private_key = ec.generate_private_key(ec.SECP256R1())", 1),
    ("signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))", 1),
    ("shared_key = private_key.exchange(ec.ECDH(), peer_public_key)", 1),
    ("jwt.encode(payload, private_key, algorithm='RS256')", 1),
    ("jwt.encode(payload, ec_key, algorithm='ES256')", 1),
    ("cipher = PKCS1_OAEP.new(rsa_key)", 1),
    ("tls_config = {'kex': 'ECDH_P256', 'auth': 'RSA_PSS_2048'}", 1),
    ("from Crypto.PublicKey import RSA, ECC", 1),
    ("pkey = crypto.PKey(); pkey.generate_key(crypto.TYPE_RSA, 2048)", 1),
    # --- Class 2: Quantum-Safe / Post-Quantum Ready (NIST FIPS 203-205 & AES-256) ---
    ("oqs.KeyEncapsulation('ML-KEM-768')", 2),
    ("kem = oqs.KeyEncapsulation('Kyber768')", 2),
    ("sig = oqs.Signature('ML-DSA-65')", 2),
    ("sig = oqs.Signature('Dilithium3')", 2),
    ("cipher = Cipher(algorithms.AES(key_256_bytes), modes.GCM(iv))", 2),
    ("aes_cipher = AES.new(key_32_bytes, AES.MODE_GCM)", 2),
    ("pqc_config = {'kem': 'ML-KEM-1024', 'sig': 'SLH-DSA-SHA2-128s'}", 2),
    ("Using AES-256-GCM for data at rest encryption", 2),
]
X_train = [x for x, _ in train_data]
y_train = [y for _, y in train_data]
# Combine token-level and character-wb n-grams to capture code syntax (like '#' comments vs '()' calls)
model = Pipeline([
    ("features", FeatureUnion([
        ("word_tfidf", TfidfVectorizer(
            token_pattern=r"[a-zA-Z0-9_#-]+",
            lowercase=True,
            ngram_range=(1, 2)
        )),
        ("char_tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5)
        ))
    ])),
    ("clf", LogisticRegression(C=10.0, max_iter=1000, random_state=42))
])
model.fit(X_train, y_train)
os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/crypto_classifier.joblib")
label_map = {
    0: "0 (NON_CRYPTO/COMMENT)",
    1: "1 (QUANTUM_VULNERABLE)",
    2: "2 (QUANTUM_SAFE_PQC)  "
}
samples = [
    "rsa.generate_private_key(key_size=2048)",
    "ec.ECDSA(hashes.SHA256())",
    "print('Hello World')",
    "# TODO: migrate RSA",
    "oqs.KeyEncapsulation('ML-KEM-768')"
]
print("PREDICTION             | CONFIDENCE | CODE SNIPPET")
print("-" * 75)
for code, pred, prob in zip(samples, model.predict(samples), model.predict_proba(samples)):
    print(f"{label_map[int(pred)]} | {max(prob):9.2%} | {code}")
