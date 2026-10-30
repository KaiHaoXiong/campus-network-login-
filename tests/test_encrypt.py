import hashlib
import unittest

import srun_encrypt


class EncryptionTests(unittest.TestCase):
    def test_keyed_md5_is_hmac_not_concatenated_md5(self):
        # RFC 2202 HMAC-MD5 test case 2, independent of either repo implementation.
        self.assertEqual(srun_encrypt.get_md5("what do ya want for nothing?", "Jefe"),
                         "750c783e6ab0b503eaa86e310a5db738")
        self.assertEqual(srun_encrypt.get_md5("abc"), "900150983cd24fb0d6963f7d28e17f72")

    def test_legacy_output_matches_original_successful_implementation(self):
        encrypted = srun_encrypt.make_encrypted_info(
            "demo@cmcc", "test123", "10.246.6.57", "8", "srun_bx1", "test_challenge_12345")
        # Captured from HEAD:srun_encrypt.py before editing, with synthetic credentials.
        self.assertEqual(hashlib.sha256(encrypted.encode()).hexdigest(),
                         "e96a80d108a0f9a527a1e1a3731bc5a24f094d89bed012875574e3052b4a3f81")

    def test_empty_input(self):
        self.assertEqual(srun_encrypt.xxtea_encode("", "key"), "")

    def test_modes_are_explicit_and_different(self):
        self.assertNotEqual(srun_encrypt.xxtea_encode("test", "key", "legacy"),
                            srun_encrypt.xxtea_encode("test", "key", "portal_js"))
        with self.assertRaises(ValueError):
            srun_encrypt.xxtea_encode("test", "key", "guess")
