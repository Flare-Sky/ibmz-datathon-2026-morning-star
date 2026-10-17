import unittest
from ai.audit import audit_source
from scanner.detect import scan_python


class FakeModel:
    classes_ = [0, 1, 2]

    def predict_proba(self, snippets):
        result = []
        for snippet in snippets:
            if "KeyEncapsulation" in snippet:
                result.append([0.02, 0.03, 0.95])
            elif "RSA.generate" in snippet:
                result.append([0.05, 0.90, 0.05])
            else:
                result.append([0.8, 0.1, 0.1])
        return result


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

    def test_unknown_rsa_goes_to_ai(self):
        report = audit_source("RSA.generate(2048)\n", "a.py", FakeModel())
        self.assertEqual(len(report["findings"]), 0)
        candidate = report["ai_candidates"][0]
        self.assertEqual(candidate["ai_class"], 1)
        self.assertEqual(candidate["ai_label"], "possibly_quantum_vulnerable")
        self.assertEqual(candidate["ai_probability"], 0.90)
        self.assertTrue(candidate["needs_human_review"])

    def test_pqc_candidate_gets_class_2(self):
        report = audit_source(
            "oqs.KeyEncapsulation('ML-KEM-768')\n", "pqc.py", FakeModel()
        )
        candidate = report["ai_candidates"][0]
        self.assertEqual(candidate["ai_class"], 2)
        self.assertEqual(candidate["ai_label"], "possibly_quantum_resistant")
        self.assertEqual(candidate["ai_probabilities"]["2"], 0.95)
        self.assertTrue(candidate["needs_human_review"])

    def test_string_with_crypto_word_is_not_a_call(self):
        report = scan_python("print('RSA')\n", "a.py")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["candidates"], [])

    def test_reject_old_binary_model(self):
        class OldModel:
            classes_ = [0, 1]

        with self.assertRaisesRegex(ValueError, "three-class model"):
            audit_source("RSA.generate(2048)\n", "a.py", OldModel())


if __name__ == "__main__":
    unittest.main()
