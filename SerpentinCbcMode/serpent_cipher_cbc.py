import secrets
from SerpentinCbcMode.serpent import hexstring2bitstring, SerpentEncryptor, bitstring2hexstring, SerpentDecryptor


# Assume all other necessary functions and classes have been correctly defined

def pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpadding(data):
    padding_len = data[-1]
    return data[:-padding_len]


def generate_random_hex_key(length):
    # Generate random bytes and convert them to a hex string
    random_bytes = secrets.token_bytes(length // 2)
    random_hex_key = random_bytes.hex()
    return random_hex_key


class SerpentCipherCBC:
    def __init__(self, userKey):
        self.encryptor = SerpentEncryptor(userKey)
        self.decryptor = SerpentDecryptor(userKey)

    def xor_bitstrings(self, bitstring1, bitstring2):
        try:
            # Ensure both bitstrings are of equal length
            assert len(bitstring1) == len(bitstring2) == 128
            return ''.join(str(int(a) ^ int(b)) for a, b in zip(bitstring1, bitstring2))
        except Exception as e:
            print(e)
            return None

    def encrypt_cbc(self, plaintext, iv):
        try:
            # Ensure plaintext is properly padded and split into 128-bit blocks
            padded_plaintext = pkcs7_padding(plaintext.encode('utf-8'))
            blocks = [padded_plaintext[i:i + 16] for i in range(0, len(padded_plaintext), 16)]

            iv_bitstring = hexstring2bitstring(iv.hex())
            encrypted_blocks = []

            for block in blocks:
                block_bitstring = hexstring2bitstring(block.hex())
                xor_block = self.xor_bitstrings(iv_bitstring, block_bitstring)
                encrypted_block_hex = self.encryptor.encrypt(bitstring2hexstring(xor_block))
                encrypted_blocks.append(encrypted_block_hex)
                iv_bitstring = hexstring2bitstring(encrypted_block_hex)

            return ''.join(encrypted_blocks)
        except Exception as e:
            print(e)
            return None

    def decrypt_cbc(self, ciphertext, iv):
        try:
            # Split ciphertext into blocks of 32 hex characters (128 bits)
            blocks = [ciphertext[i:i + 32] for i in range(0, len(ciphertext), 32)]

            iv_bitstring = hexstring2bitstring(iv.hex())
            decrypted_blocks = []

            for block in blocks:
                decrypted_block_hex = self.decryptor.decrypt(block)
                decrypted_block_bitstring = hexstring2bitstring(decrypted_block_hex)
                xor_block = self.xor_bitstrings(iv_bitstring, decrypted_block_bitstring)
                decrypted_blocks.append(bitstring2hexstring(xor_block))
                iv_bitstring = hexstring2bitstring(block)

            decrypted_data = b''.join([bytes.fromhex(block) for block in decrypted_blocks])
            return pkcs7_unpadding(decrypted_data).decode('utf-8')
        except Exception as e:
            print(e)
            return None
