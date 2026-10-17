import unittest
from ai.audit import audit_source
from scanner.detect import scan_python


class FakeModel:
    classes_ = [0, 1]

    def predict_proba(self, snippets):
        return [[0.35, 0.65] for _ in snippets]


class TestAIIntegration(unittest.TestCase):
    def test_known_call_is_a_rule_finding(self):
        code = (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "rsa.generate_private_key(key_size=2048)\n"
        )
        report = audit_source(code, "a.py", FakeModel())
        self.assertEqual(report["findings"][0]["algorithm"], "RSA")
        self.assertEqual(report["findings"][0]["confidence"], "high")
        self.assertEqual(len(report["ai_candidates"]), 0)

    def test_unknown_crypto_call_goes_to_ai(self):
        code = "RSA.generate(2048)\n"
        report = audit_source(code, "a.py", FakeModel())
        self.assertEqual(len(report["findings"]), 0)
        candidate = report["ai_candidates"][0]
        self.assertEqual(candidate["ai_label"], "possibly_crypto_usage")
        self.assertEqual(candidate["ai_probability_class_1"], 0.65)
        self.assertTrue(candidate["needs_human_review"])

    def test_string_with_crypto_word_is_not_a_call(self):
        report = scan_python("print('RSA')\n", "a.py")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["candidates"], [])


if __name__ == "__main__":
    unittest.main()
