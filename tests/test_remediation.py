import unittest
from ai.remediation import build_remediation


class RemediationTests(unittest.TestCase):
    def test_rsa_migration_depends_on_usage(self):
        r, plan = build_remediation([{
            "file": "sample.py", "line": 4, "algorithm": "RSA",
            "quantum_status": "vulnerable", "confidence": "high",
            "evidence": "rsa.generate_private_key"
        }], [])
        self.assertEqual(r[0]["priority"], "High")
        self.assertIn("ML-KEM", " ".join(r[0]["next_steps"]))
        self.assertIn("ML-DSA", " ".join(r[0]["next_steps"]))
        self.assertEqual(len(plan), 3)

    def test_aes_does_not_recommend_replacing_with_pqc(self):
        r, _ = build_remediation([{
            "algorithm": "AES-GCM", "quantum_status": "review",
            "confidence": "high", "file": "a.py", "line": 1
        }], [])
        self.assertEqual(r[0]["priority"], "Review")
        self.assertIn("nonce", r[0]["recommended_action"])
        self.assertIn("do not replace", r[0]["recommended_action"])

    def test_pqc_prediction_is_not_certification(self):
        r, _ = build_remediation([], [{
            "file": "a.py", "line": 2, "evidence": "oqs.Signature",
            "ai_class": 2, "ai_probability": 0.99
        }])
        self.assertEqual(r[0]["priority"], "Review")
        self.assertTrue(r[0]["needs_human_review"])
        self.assertIn("does not prove", r[0]["why"])

    def test_low_confidence_rule_not_automatic_high(self):
        r, _ = build_remediation([{
            "algorithm": "RSA", "quantum_status": "vulnerable",
            "confidence": "low", "file": "a.py", "line": 1
        }], [])
        self.assertEqual(r[0]["priority"], "Review")
        self.assertIn("verify", r[0]["recommended_action"])

    def test_high_priority_before_ai_candidates(self):
        r, _ = build_remediation([{
            "algorithm": "RSA", "quantum_status": "vulnerable",
            "confidence": "high", "file": "a.py", "line": 3
        }], [{"ai_class": 1, "file": "b.py", "line": 1}])
        self.assertEqual([x["source_type"] for x in r],
                         ["rule_finding", "ai_candidate"])


if __name__ == "__main__":
    unittest.main()
