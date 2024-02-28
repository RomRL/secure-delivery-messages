# Initialize and use the cipher
import os

from SerpentinCbcMode.SerpentCipherCBC import SerpentCipherCBC
from SerpentinCbcMode.serpent import hexstring2bitstring

if __name__ == "__main__":
    hexKey = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"
    userKey = hexstring2bitstring(hexKey).ljust(256, '0')[:256]  # Adjust as necessary
    iv = os.urandom(16)  # Random IV for CBC mode
    serpent_cipher = SerpentCipherCBC(userKey)

    plaintext = "This is a message that is longer than 128 bits..."
    encrypted = serpent_cipher.encrypt_cbc(plaintext, iv)
    decrypted = serpent_cipher.decrypt_cbc(encrypted, iv)

    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
