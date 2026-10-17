# Morning Star — Quantum-Safe Crypto Auditor

Morning Star is a static-analysis prototype for finding cryptographic API usage in Python source code. It combines deterministic AST rules with an optional machine-learning classifier hosted on IBM LinuxONE, then presents the results through a command-line interface or a Streamlit web app.

The scanner parses uploaded code but does **not** execute it.

> [!IMPORTANT]
> This project supports code review; it does not prove that code is secure or insecure. Rule matches identify known API usage, while all ML predictions are unverified suggestions that require human review.

## What it detects

The rule-based scanner currently recognizes these Python call patterns:

| Algorithm/API | Reported status | Notes |
| --- | --- | --- |
| RSA key generation | `vulnerable` | Public-key primitive vulnerable to a sufficiently capable quantum computer |
| ECC key generation | `vulnerable` | Includes recognized `cryptography` EC key-generation calls |
| ECDSA | `vulnerable` | Digital-signature usage |
| ECDH | `vulnerable` | Key-establishment usage |
| AES-GCM | `review` | Symmetric cryptography; review key size, key management, and surrounding usage |

Calls with crypto-related names that do not match a verified rule—such as a post-quantum `ML-KEM` API—are emitted as candidates. When the optional AI layer is enabled, a three-class model labels each candidate as:

- `possibly_non_crypto_or_comment`
- `possibly_quantum_vulnerable`
- `possibly_quantum_resistant`

These labels are hints, not security findings.

## Architecture

```text
Python source
     │
     ▼
AST rule scanner ──────► verified rule findings
     │
     └─ unknown crypto-like calls
                  │
                  ▼
       three-class ML model on LinuxONE
                  │
                  ▼
          human-review candidates
```

The Streamlit frontend sends a Python file to the authenticated LinuxONE API. The API runs the rule scanner and model, then returns rule findings and AI candidates as JSON.

## Repository layout

```text
.
├── App.py                  # Streamlit frontend
├── linuxone_api_server.py  # Authenticated local-only HTTP API
├── run_scan.py             # Single-file rule-scanner example
├── run_project.py          # Directory rule scanner
├── run_ai_audit.py         # File/directory rule + AI CLI
├── scanner/                # AST detection and project traversal
├── ai/                     # Model loading and audit integration
├── samples/                # Static-analysis examples; do not execute ai_demo.py
├── tests/                  # unittest test suite
└── data/                   # Demonstration training data
```

## Requirements

- Python 3.9 or newer
- Streamlit frontend: packages in `requirements.txt`
- AI inference or training: `joblib` and `scikit-learn`
- A separately trained three-class model for AI auditing

No trained model or model weights are included in this repository.

## Quick start: rule-based scanner

Clone the repository and create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Scan the bundled single-file example:

```bash
python3 run_scan.py
```

Scan every Python file under a directory:

```bash
python3 run_project.py samples
```

`run_project.py` uses `samples` when no directory is supplied. Project scans skip `.git`, virtual environments, `__pycache__`, and `node_modules`; they scan at most 100 Python files and reject files larger than 1 MB.

## Run the tests

The tests use a fake three-class model, so they do not require scikit-learn or a model artifact:

```bash
python3 -m unittest discover -s tests -v
```

## AI-assisted audit on LinuxONE

Install the ML runtime on the LinuxONE environment:

```bash
/usr/bin/python3 -m pip install joblib scikit-learn
```

The model supplied to the audit must expose `predict_proba`, and its `classes_` must contain exactly `0`, `1`, and `2`. Only load a trusted model that you generated yourself: loading a `joblib` file can execute code.

Audit one file:

```bash
/usr/bin/python3 run_ai_audit.py samples/ai_demo.py \
  --model /home/linux1/models/crypto_classifier_v2.joblib
```

Audit a directory:

```bash
/usr/bin/python3 run_ai_audit.py samples \
  --model /home/linux1/models/crypto_classifier_v2.joblib
```

### Training-script compatibility

`train_model.py` and `data/crypto_training.csv` currently demonstrate a **binary** classifier with labels `0` and `1`. The resulting artifact is not compatible with the three-class AI audit described above. Use a separately trained and validated model whose classes are exactly `[0, 1, 2]`.

## Run the LinuxONE API

The API binds to `127.0.0.1:8765`, accepts source files up to 256 KiB, and protects `POST /audit` with a bearer token.

```bash
export QSAFE_API_TOKEN='replace-with-a-long-random-token'
export QSAFE_MODEL_PATH='/home/linux1/models/crypto_classifier_v2.joblib'
/usr/bin/python3 linuxone_api_server.py
```

Check service health:

```bash
curl http://127.0.0.1:8765/health
```

Submit an audit request:

```bash
curl -X POST http://127.0.0.1:8765/audit \
  -H "Authorization: Bearer ${QSAFE_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{"filename":"example.py","source":"RSA.generate(2048)"}'
```

Keep this service bound to localhost and expose it only through a trusted tunnel or reverse proxy with TLS.

## Run the Streamlit frontend

Create `.streamlit/secrets.toml` locally:

```toml
LINUXONE_API_URL = "https://your-secure-endpoint.example/audit"
LINUXONE_API_TOKEN = "the-same-token-used-by-the-api"
```

The secrets file is ignored by Git and must not be committed. Start the app with:

```bash
streamlit run App.py
```

Upload a UTF-8 encoded `.py` file, run the audit, and review the rule findings, AI candidates, and raw JSON report. Results can also be downloaded as CSV or JSON.

## Output model

A successful audit returns an object shaped like this:

```json
{
  "findings": [
    {
      "file": "example.py",
      "line": 2,
      "algorithm": "RSA",
      "usage": "unknown",
      "quantum_status": "vulnerable",
      "evidence": "rsa.generate_private_key",
      "confidence": "high",
      "key_size": 2048
    }
  ],
  "ai_candidates": [],
  "summary": {
    "rule_findings": 1,
    "ai_candidates_for_review": 0
  }
}
```

High-confidence findings are tied to recognized, fully qualified imports. Unqualified name matches are reported with low confidence. Syntax errors and unreadable files are recorded as project-scan errors instead of stopping the whole scan.

## Security and limitations

- Only Python source is supported.
- Detection is based on a small rule set and can miss wrappers, aliases created at runtime, indirect calls, and unsupported libraries.
- A rule match identifies API usage; it does not assess the complete protocol, deployment, or threat model.
- AI probabilities are model outputs, not calibrated security confidence.
- Uploaded code is parsed but not executed by the scanner. It is still transmitted to the configured backend, so deploy the frontend, tunnel, API, and logs according to your data-handling requirements.
- Do not execute `samples/ai_demo.py`; it is input for static analysis and intentionally contains unresolved names.
