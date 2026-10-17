# Morning Star — Quantum-Safe Crypto Auditor & Migration Planner

**IBM Z Datathon 2026 · Team Morning Star**

**Discover cryptographic exposure today. Prioritize a quantum-safe tomorrow.**

Morning Star helps schools, nonprofits, and small IT teams identify potential quantum-vulnerable cryptography in Python source code and plan an explainable, business-aware migration. It combines an AST-based rule scanner, a three-class machine-learning model running on **IBM LinuxONE (s390x)**, and a Streamlit interface that generates review guidance and prioritized migration planning outputs.

**Live demonstration:** [Morning Star Streamlit app](https://ibmz-datathon-2026-morning-star1.streamlit.app/)

> [!IMPORTANT]
> **Prototype / human review required.** Morning Star does **not** establish whether an application is secure, whether a cryptographic implementation complies with NIST standards, or whether a migration is complete. It identifies recognized API usage and unverified ML candidates, then provides preliminary planning recommendations. Uploaded Python code is **parsed, never executed** by the scanner.

## What the app does

1. **Describe your organization.** Select a school, nonprofit, internal test application, or custom profile and adjust data sensitivity, confidentiality retention (1–30 years), business criticality, and migration complexity.
2. **Upload one or more `.py` files.** The Streamlit app sends each file to the authenticated IBM LinuxONE API for static analysis. Uploading multiple files does not execute or import them.
3. **Review cryptographic findings.** Known Python call patterns are reported by deterministic AST rules; unmatched crypto-like calls are classified by a three-class machine-learning model and marked for human review.
4. **Review the migration roadmap.** The Streamlit frontend combines verified rule matches, unverified candidates, and business inputs into illustrative priority tiers, recommended next checks, and a staged migration plan.
5. **Export results.** Download rule findings and the migration plan as CSV, or download a combined JSON report.

The web application includes **Home**, **Run Audit**, **How It Works**, and **NIST Reference** pages.

## Architecture and execution boundaries

```text
Browser / Streamlit Cloud (frontend)
  ├─ Organization profile, heuristic priority scoring, recommendations
  └─ File upload (one or more .py files)
           │ HTTPS + bearer token
           ▼
        ngrok tunnel
           │
           ▼
   Demonstration Mac SSH port forward
           │
           ▼
IBM LinuxONE / Ubuntu (s390x)
  └─ Localhost HTTP API :8765
       ├─ Python AST rule scanner
       └─ Three-class TF-IDF + Logistic Regression model (v3)
           │
           ▼
       Rule findings + AI candidates (JSON)
           │
           ▼
Streamlit frontend
  ├─ Explainable review recommendations (deterministic playbooks)
  ├─ Heuristic business-priority ranking and staged roadmap
  └─ CSV / JSON exports
```

**Where processing happens:** cryptographic scanning and ML inference run on LinuxONE. The business-context heuristic and remediation playbooks run in Streamlit Cloud. No third-party LLM is used to generate patches or analyze the uploaded code. However, source files traverse Streamlit Cloud and the tunnel infrastructure; **this is not a zero-exposure or on-premises-only architecture**.

**Demo availability:** the current public tunnel requires the demonstration Mac, its SSH port forward, and its ngrok session to remain connected. The backend `qsafe-api` service is independently managed with `systemd` on LinuxONE.

## Supported detection

The deterministic scanner currently recognizes the following Python call patterns:

| Rule match | Rule result | Notes |
| --- | --- | --- |
| RSA key generation | `vulnerable` | Quantum-vulnerable public-key algorithm; actual key usage must still be determined |
| Elliptic-curve key generation | `vulnerable` | Includes recognized `cryptography` EC key-generation APIs |
| ECDSA | `vulnerable` | Traditional elliptic-curve signatures |
| ECDH | `vulnerable` | Traditional elliptic-curve key agreement |
| AES-GCM | `review` | Symmetric authenticated encryption; review key length, nonce handling, tag verification, and key management |

An import-resolved, known-library call receives **high rule confidence**; a name-only pattern match receives **low rule confidence** and must be verified. A rule match establishes the occurrence of an API pattern, **not** that an application is exploitable or noncompliant.

Unknown crypto-like calls become **AI candidates**. The three-class v3 model uses:

| Class | v3 interpretation |
| --- | --- |
| `0` | Other, out of scope, or unclassified; **not** a security approval |
| `1` | Possibly quantum-vulnerable traditional asymmetric cryptography |
| `2` | Possibly post-quantum cryptographic primitive; **not** verified as safe or standards-compliant |

The existing backend API still emits the legacy class-0 string `possibly_non_crypto_or_comment`; the Streamlit UI displays class 0 as `possibly_other_or_unclassified`. **Use `ai_class` (0/1/2) as the canonical class identifier.** All AI candidates have `needs_human_review: true`. Reported ML probabilities are **not calibrated security confidence scores**.

## Business-aware migration planning

The **Prioritized Migration Plan** accounts for business inputs (sensitivity, confidentiality retention, criticality, and estimated migration complexity). The output includes priority tiers, illustrative planning scores, review guidance, indicative windows, and an exportable CSV.

- **Verified, quantum-vulnerable rule patterns** may be placed in high planning tiers, depending on business exposure.
- **Unverified AI suggestions** and **low-confidence rule matches** are kept in a **VERIFY** category rather than automatically promoted to a confirmed vulnerability.
- **AES-GCM** triggers configuration and key-management review, **not** a blanket recommendation to replace AES with ML-KEM.
- The remediation playbooks distinguish **key establishment** (evaluate ML-KEM, NIST FIPS 203) from **digital signatures** (evaluate ML-DSA or SLH-DSA, FIPS 204/205). The scanner cannot reliably infer every key's purpose from key-generation code alone.

**Important qualification:** priority scores (0–100), tier thresholds, and suggested time windows are *project-specific planning heuristics*. They are not NIST ratings, quantified breach probabilities, regulatory deadlines, validated cost estimates, or a complete implementation of Mosca's inequality. The current version is **budget-aware in prioritization**, but it does not calculate an actual dollar budget or return automatically applicable code patches.

## v3 model: training and evaluation

The deployed LinuxONE model is `crypto_classifier_v3.joblib`, a three-class **TF-IDF (word/character features) + Logistic Regression** classifier. It was trained on LinuxONE with **124 synthetic labeled examples**:

| Label | Training examples |
| --- | ---: |
| Class 0 — other / unclassified | 42 |
| Class 1 — possibly quantum-vulnerable asymmetric | 42 |
| Class 2 — possibly post-quantum primitive | 40 |

**LinuxONE evaluation (October 17, 2026; saved in `evaluation/crypto_classifier_v3_evaluation.json`):**

| Evaluation set | Examples | Accuracy | Macro F1 | Interpretation |
| --- | ---: | ---: | ---: | --- |
| Synthetic holdout | 30 | 100% (30/30) | 1.00 | Same general synthetic task distribution; not a production benchmark |
| v2 development regression | 8 | 100% (8/8) | 1.00 | Rechecks previously observed v2 misclassifications; development set |
| Out-of-family synthetic stress | 12 | 75% (9/12) | 0.74 | Exposes generalization limitations |

The out-of-family stress evaluation recorded three errors:

```text
Class 0 -> Class 2: pqcrypto.kem.ml_kem_768.get_version()
Class 0 -> Class 2: oqs.Signature('not-a-real-algorithm')
Class 1 -> Class 0: ecies.encrypt(remote_public_key, plaintext)
```

These examples show that the model does **not** authenticate the existence or standards compliance of PQC APIs and can miss less familiar cryptographic libraries. The 100% synthetic holdout result should **not** be described as real-world model accuracy. More diverse, independently sourced code examples and library-family-separated testing are necessary before operational use.

**Reproducibility:** the repository includes `train_model_v3.py` (with its synthetic training, holdout, regression, and stress examples defined in the script) and `evaluation/crypto_classifier_v3_evaluation.json` (the LinuxONE evaluation output). The trained `.joblib` binary is **not** tracked. Results can be reproduced by running the script with compatible versions of scikit-learn and its dependencies on LinuxONE. Exact dependency versions are not pinned, so bit-for-bit identical model files are not guaranteed. `train_model_v2.py` is historical prototype code and does not reproduce v3.

To regenerate **a new** v3 artifact without overwriting the deployed model:

```bash
/usr/bin/python3 train_model_v3.py \
  --output /home/linux1/models/crypto_classifier_v3_reproduced.joblib \
  --report /home/linux1/models/crypto_classifier_v3_reproduced_evaluation.json
```

Compare the resulting evaluation JSON against the committed report. Never replace a running model without independent testing and an explicit deployment step.

## Repository contents (after this documentation and evidence update)

```text
.
├── App.py                      # Streamlit multipage frontend
├── linuxone_api_server.py      # Authenticated LinuxONE-only audit API
├── run_ai_audit.py             # AI + rules CLI (single file supported by this checkout)
├── train_model_v2.py           # Historical 3-class training prototype
├── train_model_v3.py           # Three-class training + synthetic evaluation data
├── evaluation/
│   └── crypto_classifier_v3_evaluation.json  # LinuxONE evaluation evidence
├── ai/
│   ├── audit.py                # Classification and rule integration
│   ├── classifier.py           # Trusted joblib model loader
│   ├── remediation.py          # Deterministic migration playbooks
│   └── business_priority.py    # Business-context planning heuristic
├── scanner/
│   └── detect.py               # AST-based single-source scanner
├── samples/
│   └── ai_demo.py              # Sample source for static analysis
├── tests/                      # unittest tests (25 currently passing)
└── requirements.txt           # Streamlit, requests, pandas
```

**Note:** the repository does not include the optional project-directory scanner (`scanner/project.py`, `run_project.py`) or older standalone `run_scan.py`. The **web app supports multiple files** by sending them individually to the LinuxONE API and combining the results; this is separate from a CLI directory traversal feature. The `audit_project()` function in `ai/audit.py` expects `scanner/project.py` and therefore is **not available from a fresh clone of the current `main`**.

## Running the project

### 1. Frontend dependencies and unit tests

Python **3.9+** is required for the AST scanner. In a local clone:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

At the October 17 checkpoint, the repository's 25 unit tests passed on the project Mac. Tests cover scanner rules, simulated three-class AI integration, remediation rules, and business priority behavior. **AI unit tests use a fake model** and do not establish the actual v3 model's accuracy.

### 2. LinuxONE model inference

The datathon LinuxONE machine uses Ubuntu 24.04 on `s390x`. On the environment used for the demo, system packages were installed using APT:

```bash
sudo apt-get update
sudo apt-get install -y python3-numpy python3-scipy python3-sklearn python3-joblib
```

The inference server requires a **trusted, separately created** three-class joblib model. Only load artifacts you control: unpickling a malicious joblib artifact may execute code.

Run a local AI-assisted audit on LinuxONE:

```bash
cd ~/ibmz-datathon-2026-morning-star
/usr/bin/python3 run_ai_audit.py samples/ai_demo.py \
  --model /home/linux1/models/crypto_classifier_v3.joblib
```

The sample file includes intentionally unresolved names. **Do not execute it**; use it strictly as scanner input.

### 3. LinuxONE HTTP API

The backend binds to `127.0.0.1:8765`, limits POST request bodies to **256 KiB**, and protects `POST /audit` with a bearer token. Its unauthenticated `GET /health` endpoint returns service state and loaded class IDs.

```bash
export QSAFE_API_TOKEN='replace-with-a-long-random-token'
export QSAFE_MODEL_PATH='/home/linux1/models/crypto_classifier_v3.joblib'
/usr/bin/python3 linuxone_api_server.py
```

For the deployed instance, the token and model path are managed by its LinuxONE `systemd` service configuration. **Do not publish tokens, configuration secrets, or private keys.**

Check LinuxONE local health:

```bash
curl http://127.0.0.1:8765/health
```

Example authenticated audit request:

```bash
curl -X POST http://127.0.0.1:8765/audit \
  -H "Authorization: Bearer ${QSAFE_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"filename":"example.py","source":"RSA.generate(2048)"}'
```

A missing or incorrect bearer token returns `401`; malformed input returns `400`; oversized POST bodies return `413`. A health response reporting classes `[0,1,2]` does **not** alone prove which model version was loaded; check the actual service environment/model path for that.

### 4. Streamlit interface

The hosted demonstration uses Streamlit Community Cloud. For a local development setup, create `.streamlit/secrets.toml` (ignored by Git):

```toml
LINUXONE_API_URL = "https://YOUR_SECURE_ENDPOINT/audit"
LINUXONE_API_TOKEN = "THE_BACKEND_BEARER_TOKEN"
```

```bash
streamlit run App.py
```

The frontend sends its bearer token in the `Authorization` header and uses an ngrok-specific skip-warning header for the present demo tunnel. The deployed Streamlit Cloud app stores secrets in its own deployment settings, not in GitHub.

## Example: expected end-to-end behavior

When given this **source text** (not executed):

```python
from cryptography.hazmat.primitives.asymmetric import rsa
rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA.generate(2048)
oqs.KeyEncapsulation('ML-KEM-768')
print('RSA is mentioned')
```

The AST rules produce one RSA finding. Unrecognized RSA and ML-KEM API calls are sent to the model as two **review-required** candidates, while the final string literal is not itself treated as a crypto call. In the LinuxONE v3 CLI test, `RSA.generate(2048)` was classified as class 1 and the ML-KEM call as class 2. This **does not prove** that either call is correctly implemented or secure.

The business profile can change the **planning priority**, but must not change the underlying cryptographic classifications.

## Security, privacy, and limitations

- Source is statically parsed but **not executed**. This does not guarantee the absence of all possible parsing, dependency, or infrastructure vulnerabilities.
- The tool supports **Python** source only and recognizes a limited set of AST call patterns; dynamic references, unsupported APIs, wrappers, and runtime aliasing may be missed.
- AI suggestions require human review. **Class 0 is not a safety finding; class 2 is not a NIST-compliance certification.**
- Planning scores, effort bands, and time windows are illustrative heuristics, not objective risk measurements or project-cost estimates.
- Current testing consists of prototype unit tests and small synthetic model evaluations, not a comprehensive independent security assessment.
- Uploaded code travels via the browser, Streamlit Cloud, the HTTPS tunnel and an SSH port forward to LinuxONE. Do not upload confidential source code without an appropriate data-handling review.
- The current demo tunnel depends on an online Mac and may be unavailable when the tunnel or SSH session stops.
- No automatic code refactoring or migration is performed; users must verify the proposed cryptographic replacements and test protocol compatibility.

## Project status

**Deployed demo:** IBM LinuxONE v3 inference + authenticated API + Streamlit multi-file frontend + explainable business-priority migration guidance. **Research prototype; human verification required.**
