import unittest
import os
from SerpentinCbcMode.serpent import hexstring2bitstring
from SerpentinCbcMode.serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key


class TestSerpentCipher(unittest.TestCase):
    def setUp(self):
        self.hexKey = generate_random_hex_key(64)  # 256-bit keyc
        self.userKey = hexstring2bitstring(self.hexKey)
        self.iv = os.urandom(16)  # Random IV for CBC modes
        self.serpent_cipher = SerpentCipherCBC(self.userKey)

    def test_encrypt_decrypt(self):
        plaintext = "This is a message that is longer than 128 bits..."
        encrypted = self.serpent_cipher.encrypt_cbc(plaintext, self.iv)
        decrypted = self.serpent_cipher.decrypt_cbc(encrypted, self.iv)
        self.assertEqual(decrypted, plaintext, "Decrypted message does not match original plaintext")


if __name__ == '__main__':
    unittest.main()
