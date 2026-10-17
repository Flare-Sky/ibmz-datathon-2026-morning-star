import unittest
from scanner.detect import scan_python


class TestCryptoScanner(unittest.TestCase):

    def test_rsa(self):
        code = """
rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
"""
        result = scan_python(code, "rsa.py")
        self.assertEqual(
            result["findings"][0]["algorithm"], "RSA"
        )
        self.assertEqual(
            result["findings"][0]["quantum_status"],
            "vulnerable"
        )

    def test_ecc(self):
        code = "ec.generate_private_key(ec.SECP256R1())"
        result = scan_python(code, "ecc.py")
        self.assertEqual(
            result["findings"][0]["algorithm"], "ECC"
        )

    def test_ecdsa(self):
        code = "ec.ECDSA(hashes.SHA256())"
        result = scan_python(code, "sign.py")
        self.assertEqual(
            result["findings"][0]["algorithm"], "ECDSA"
        )

    def test_aes(self):
        code = "cipher = AESGCM(key)"
        result = scan_python(code, "aes.py")
        self.assertEqual(
            result["findings"][0]["algorithm"], "AES-GCM"
        )
        self.assertEqual(
            result["findings"][0]["quantum_status"],
            "review"
        )

    def test_comments_are_not_crypto_calls(self):
        code = """
# We use RSA encryption
message = "AESGCM"
"""
        result = scan_python(code, "comments.py")
        self.assertEqual(len(result["findings"]), 0)

    def test_multiple_algorithms(self):
        code = """
rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
ec.generate_private_key(ec.SECP256R1())
"""
        result = scan_python(code, "mixed.py")
        self.assertEqual(len(result["findings"]), 2)


    def test_import_alias(self):
        code = """
from cryptography.hazmat.primitives.asymmetric import rsa as r
key = r.generate_private_key(key_size=2048)
"""
        result = scan_python(code, "alias.py")
        finding = result["findings"][0]

        self.assertEqual(finding["algorithm"], "RSA")
        self.assertEqual(finding["key_size"], 2048)
        self.assertEqual(finding["confidence"], "high")

    def test_function_alias(self):
        code = """
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as make_key
key = make_key(key_size=4096)
"""
        result = scan_python(code, "alias2.py")
        finding = result["findings"][0]

        self.assertEqual(finding["algorithm"], "RSA")
        self.assertEqual(finding["key_size"], 4096)

    def test_unrelated_import(self):
        code = """
from fake_crypto import rsa
rsa.generate_private_key()
"""
        result = scan_python(code, "fake.py")

        self.assertEqual(len(result["findings"]), 0)

if __name__ == "__main__":
    unittest.main()
