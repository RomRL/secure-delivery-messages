import unittest
import os
from SerpentinCbcMode.serpent import hexstring2bitstring
from SerpentinCbcMode.serpent_cipher_cbc import SerpentCipherCBC, generate_random_hex_key
from ElGamal.el_gamal import generate_keypair, encrypt_key, decrypt_key


class TestSerpentCipher(unittest.TestCase):
    def setUp(self):
        public_key_alise, private_key_alise = generate_keypair()
        public_key_bob, private_key_bob = generate_keypair()
        # print("Public key Alise:", public_key_alise, "Private key Alise:", private_key_alise)
        # print("Public key Bob:", public_key_bob, "Private key Bob:", private_key_bob)
        self.hexKey = generate_random_hex_key(64)  # 64 *4 (size of hex) =  256-bit keyc
        key_to_transport = int(self.hexKey, 16)    # convert hex to int
        print("Original key:", key_to_transport)

        ciphertext_alise = encrypt_key(key_to_transport, public_key_bob)
        print("Encrypted key:", ciphertext_alise)

        # BOB GETS THE CIPHERTEXT AND DECRYPTS IT USING HIS PRIVATE KEY
        decrypted_key_bob = decrypt_key(ciphertext_alise, private_key_bob, public_key_bob)

        print("Decrypted key:", decrypted_key_bob)
        # convert int to hex
        self.userKey = hexstring2bitstring(hex(decrypted_key_bob)[2:])

        self.iv = os.urandom(16)  # Random IV for CBC modes 16 bytes = 128 bits

        self.serpent_cipher = SerpentCipherCBC(self.userKey)

    def test_encrypt_decrypt(self):
        plaintext = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
        encrypted = self.serpent_cipher.encrypt_cbc(plaintext, self.iv)
        decrypted = self.serpent_cipher.decrypt_cbc(encrypted, self.iv)
        self.assertEqual(decrypted, plaintext, "Decrypted message does not match original plaintext")


if __name__ == '__main__':
    unittest.main()
