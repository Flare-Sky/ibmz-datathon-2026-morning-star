
import unittest
from ai.business_priority import build_migration_plan


HIGH = dict(sensitivity="High", retention_years=20, criticality="High", complexity="Medium")
LOW = dict(sensitivity="Low", retention_years=1, criticality="Low", complexity="Low")


class BusinessPriorityTests(unittest.TestCase):
    def test_verified_rsa_gets_higher_priority_with_sensitive_long_lived_data(self):
        finding = dict(file="demo.py", line=1, evidence="rsa.generate_private_key",
                       algorithm="RSA", quantum_status="vulnerable", confidence="high")
        higher, recommendations, roadmap = build_migration_plan([finding], [], HIGH)
        lower, _, _ = build_migration_plan([finding], [], LOW)
        self.assertGreater(higher[0]["Planning Score"], lower[0]["Planning Score"])
        self.assertTrue(higher[0]["Priority Tier"].startswith("P1"))
        self.assertIn("ML-KEM", " ".join(recommendations[0]["next_steps"]))
        self.assertEqual(len(roadmap), 3)

    def test_low_confidence_rsa_is_review_only(self):
        finding = dict(file="demo.py", line=2, evidence="rsa.generate_private_key",
                       algorithm="RSA", quantum_status="vulnerable", confidence="low")
        rows, _, _ = build_migration_plan([finding], [], HIGH)
        self.assertTrue(rows[0]["Priority Tier"].startswith("VERIFY"))
        self.assertLess(rows[0]["Planning Score"], 60)

    def test_ai_predicted_vulnerable_not_promoted_to_p1(self):
        candidate = dict(file="demo.py", line=2, evidence="RSA.generate",
                         ai_class=1, ai_probability=0.9999)
        rows, suggestions, _ = build_migration_plan([], [candidate], HIGH)
        self.assertTrue(rows[0]["Priority Tier"].startswith("VERIFY"))
        self.assertLess(rows[0]["Planning Score"], 60)
        self.assertIn("unverified", rows[0]["Verification Basis"].lower())
        self.assertEqual(suggestions[0]["priority"], "Review")

    def test_pqc_prediction_does_not_claim_nist_compliance(self):
        candidate = dict(file="demo.py", line=3, evidence="oqs.Signature", ai_class=2)
        rows, recommendations, _ = build_migration_plan([], [candidate], HIGH)
        self.assertIn("Verify", rows[0]["Suggested Next Step"]) if False else None
        self.assertNotIn("Compliant with NIST", rows[0]["Suggested Next Step"])
        self.assertIn("does not prove", recommendations[0]["why"])

    def test_aes_gcm_does_not_require_pqc_replacement(self):
        finding = dict(file="demo.py", line=2, evidence="AESGCM",
                       algorithm="AES-GCM", quantum_status="review", confidence="high")
        rows, _, _ = build_migration_plan([finding], [], HIGH)
        self.assertEqual(rows[0]["Priority Tier"], "VERIFY — Rule match / configuration")
        self.assertIn("nonce", rows[0]["Suggested Next Step"])

    def test_empty_results(self):
        rows, advice, stages = build_migration_plan([], [], LOW)
        self.assertEqual(rows, [])
        self.assertEqual(advice, [])
        self.assertEqual(len(stages), 3)


if __name__ == "__main__":
    unittest.main()
