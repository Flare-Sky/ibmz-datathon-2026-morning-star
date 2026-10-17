# Q-Safe Scanner + AI Integration

## Contents

- `scanner/detect.py`: updated detection code: known findings and unknown crypto-like call candidates
- `ai/classifier.py`: trusted model loader
- `ai/audit.py`: integration API, `audit_source()`, `audit_project()`, and `analyze_report()`
- `run_ai_audit.py`: command-line demonstration
- `tests/test_ai_audit.py`: 3 unit tests, no scikit-learn required
- `samples/ai_demo.py`: sample *source for static analysis only*, do not execute

## Deploy in a local checkout

Copy contents into project root, preserving directories. This package intentionally replaces `scanner/detect.py`. Your existing `scanner/project.py` and other files remain untouched.

Local Mac tests (no sklearn required):

    python3 -m unittest discover -s tests -v

After commit/merge, in the LinuxONE SSH shell:

    cd ~/ibmz-datathon-2026-morning-star
    git pull --ff-only
    /usr/bin/python3 run_ai_audit.py samples/ai_demo.py --model /home/linux1/models/crypto_classifier.joblib

If `scanner/project.py` is present (Phase 4 merged), you can scan directories too:

    /usr/bin/python3 run_ai_audit.py samples --model /home/linux1/models/crypto_classifier.joblib

All ML outputs are suggestions needing human review. A model prediction is not a security vulnerability determination. Do not copy incompatible Mac-trained model artifacts: use the model you generated on LinuxONE.
