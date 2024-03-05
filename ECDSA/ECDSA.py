import hashlib
import random

# Define the elliptic curve parameters for the P-256 curve
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (Gx, Gy)

# Elgamal c1 and c2 cipher text message
c1 = "449f682509c223a6a9449a6228f5d22183a2755b212f39fb4eeabb86ad0597b768af49f33cbf95a7565973550a186f5793d0d4a5b60e06aa50c9992dbab59c246ec9df2f9138b9c2a6ced7f1483062083859f46881c58b02b72a10936cd29fc0"
c2 = "88c0559d7818bc37962e17a80ffc25cea6a664f705b549c044fe179cee142952885c8b5edad9f806abace31fc158741dea87aa8727c59d74f6bee461ff07ce696ec9df2f9138b9c2a6ced7f1483062083859f46881c58b02b72a10936cd29fc0"


# Elliptic curve point addition
def point_add(point1, point2):
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    if point1[0] == point2[0] and point1[1] != point2[1]:
        return None
    if point1 == point2:
        lam = (3 * point1[0] ** 2 + a) * pow(2 * point1[1], p - 2, p)
    else:
        lam = (point2[1] - point1[1]) * pow(point2[0] - point1[0], p - 2, p)
    x3 = (lam ** 2 - point1[0] - point2[0]) % p
    y3 = (lam * (point1[0] - x3) - point1[1]) % p
    return (x3, y3)

# Elliptic curve point multiplication
def point_mul(point, n):
    result = None
    addend = point
    while n:
        if n & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        n >>= 1
    return result

# Generate a private key for Alice and Bob
def gen_private_key():
    return random.randrange(1, n)

# Calculate the public key corresponding to a private key
def get_public_key(private_key):
    return point_mul(G, private_key)

# ECDSA signature generation
def sign(private_key, message):
    z = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    r = 0
    s = 0
    while r == 0 or s == 0:
        k = random.randrange(1, n)
        x, _ = point_mul(G, k)
        r = x % n
        s = pow(k, n - 2, n) * (z + r * private_key) % n
    return (r, s)

# ECDSA signature verification
def verify(public_key, message, signature):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False
    z = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    w = pow(s, n - 2, n)
    u1 = z * w % n
    u2 = r * w % n
    x, _ = point_add(point_mul(G, u1), point_mul(public_key, u2))
    return x % n == r

# Alice and Bob exchange public keys
alice_private_key = gen_private_key()
alice_public_key = get_public_key(alice_private_key)
bob_private_key = gen_private_key()
bob_public_key = get_public_key(bob_private_key)

# Alice sends a message to Bob
message = "Hello, Bob!"
# Elgamal c1 and c2 cipher text message
message_ELGmal = (c1, c2)
new_message = ''.join(message_ELGmal)
signature = sign(alice_private_key, new_message)

# signature for string message
# signature = sign(alice_private_key, message)

# Bob verifies the message
verification = verify(alice_public_key, new_message, signature)
print("Verification:", verification)
