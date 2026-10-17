"""Local-only audit API on IBM LinuxONE. Access through an SSH tunnel.

Run from the repository root using: /usr/bin/python3 linuxone_api_server.py
No third-party HTTP server dependency is needed.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ai.audit import audit_source
from ai.classifier import load_model

MODEL_PATH = os.environ.get(
    "QSAFE_MODEL_PATH", "/home/linux1/models/crypto_classifier_v2.joblib"
)
MODEL = load_model(MODEL_PATH)
MAX_BODY = 256 * 1024


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {
                "status": "ok",
                "service": "Q-Safe Crypto Auditor",
                "inference_host": "LinuxONE",
                "model_classes": [int(v) for v in MODEL.classes_],
            })
        self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/audit":
            return self.send_json(404, {"error": "not_found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json(400, {"error": "invalid_content_length"})
        if not 0 < size <= MAX_BODY:
            return self.send_json(413, {"error": "request_must_be_1_to_262144_bytes"})
        try:
            payload = json.loads(self.rfile.read(size))
            source = payload["source"]
            filename = payload.get("filename", "uploaded.py")
            if not isinstance(source, str) or not isinstance(filename, str):
                raise ValueError("source and filename must be strings")
            if not source or len(filename) > 200:
                raise ValueError("source must be nonempty and filename <= 200 characters")
            filename = os.path.basename(filename)
            report = audit_source(source, filename, MODEL)
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, SyntaxError) as exc:
            return self.send_json(400, {"error": "invalid_input", "detail": str(exc)[:250]})
        except Exception:
            self.log_exception_safely()
            return self.send_json(500, {"error": "internal_audit_error"})
        self.send_json(200, report)

    def log_exception_safely(self):
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    address = ("127.0.0.1", 8765)
    print(f"LinuxONE Q-Safe API at http://{address[0]}:{address[1]}", flush=True)
    ThreadingHTTPServer(address, Handler).serve_forever()
