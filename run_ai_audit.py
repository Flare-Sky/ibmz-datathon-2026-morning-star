"""Example: /usr/bin/python3 run_ai_audit.py samples/sample.py --model ~/models/crypto_classifier.joblib"""
import argparse
import json
from pathlib import Path

from ai.audit import audit_source, audit_project
from ai.classifier import load_model


def main():
    parser = argparse.ArgumentParser(description="Q-Safe Scanner + AI audit")
    parser.add_argument("source_file", help="Python source file or project directory")
    parser.add_argument(
        "--model", default="~/models/crypto_classifier.joblib",
        help="Path to your own LinuxONE-trained joblib model",
    )
    args = parser.parse_args()
    path = Path(args.source_file)
    model = load_model(args.model)
    if path.is_dir():
        report = audit_project(path, model)
    else:
        source = path.read_text(encoding="utf-8")
        report = audit_source(source, str(path), model)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
