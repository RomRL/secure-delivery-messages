import hashlib
import random

class ECDSA:
    def __init__(self):
        # Define the elliptic curve parameters for the P-256 curve
        self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        self.a = -3
        self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
        self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        self.Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
        self.Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        self.G = (self.Gx, self.Gy)

    def point_add(self, point1, point2):
        # Elliptic curve point addition
        if point1 is None:
            return point2
        if point2 is None:
            return point1
        if point1[0] == point2[0] and point1[1] != point2[1]:
            return None
        if point1 == point2:
            lam = (3 * point1[0] ** 2 + self.a) * pow(2 * point1[1], self.p - 2, self.p)
        else:
            lam = (point2[1] - point1[1]) * pow(point2[0] - point1[0], self.p - 2, self.p)
        x3 = (lam ** 2 - point1[0] - point2[0]) % self.p
        y3 = (lam * (point1[0] - x3) - point1[1]) % self.p
        return (x3, y3)

    def point_mul(self, point, n):
        # Elliptic curve point multiplication
        result = None
        addend = point
        while n:
            if n & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            n >>= 1
        return result

    def gen_private_key(self):
        # Generate a private key
        return random.randrange(1, self.n)

    def get_public_key(self, private_key):
        # Calculate the public key corresponding to a private key
        return self.point_mul(self.G, private_key)

    def sign(self, private_key, message):
        # ECDSA signature generation
        e = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        r = 0
        s = 0
        while r == 0 or s == 0:
            k = random.randrange(1, self.n)
            x, _ = self.point_mul(self.G, k)
            r = x % self.n
            s = pow(k, self.n - 2, self.n) * (e + r * private_key) % self.n
        return (r, s)

    def verify(self, public_key, message, signature):
        # ECDSA signature verification
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        e = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        w = pow(s, self.n - 2, self.n)
        u1 = e * w % self.n
        u2 = r * w % self.n
        x, _ = self.point_add(self.point_mul(self.G, u1), self.point_mul(public_key, u2))
        return x % self.n == r

    def gen_ecdsa_key_pair(self):
        # Generate a key pair
        private_key = self.gen_private_key()
        public_key = self.get_public_key(private_key)
        return public_key, private_key
    
# Example usage
ecdsa = ECDSA()
alice_private_key = ecdsa.gen_private_key()
alice_public_key = ecdsa.get_public_key(alice_private_key)
bob_private_key = ecdsa.gen_private_key()
bob_public_key = ecdsa.get_public_key(bob_private_key)

message = "Hello, Bob!"
signature = ecdsa.sign(alice_private_key, message)
verification = ecdsa.verify(alice_public_key, message, signature)
print("Verification:", verification)
