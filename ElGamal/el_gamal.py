import random


# Extended Euclidean Algorithm to find modular inverse
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


# Modular inverse using Extended Euclidean Algorithm
def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m


# Fast modular exponentiation using square and multiply algorithm
def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result


# Generate random prime number
def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate


# Check if a number is prime using Fermat's primality test
def is_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if mod_exp(a, n - 1, n) != 1:
            return False
    return True


# Generate ElGamal key pair
def generate_keypair(p:int,g:int):
    # Generate private key x
    k = random.randint(2, p - 2)
    # Calculate public key y
    y = mod_exp(g, k, p)
    return (p, g, y), k


# Encrypt key (message)
def encrypt_key(key,private_key, public_key):
    p, g, y = public_key
    k = random.randint(2, p - 2)
    c1 = mod_exp(g, private_key, p)
    s = mod_exp(y, private_key, p)
    c2 = (s * key) % p
    return c1, c2


# Decrypt key (message)
def decrypt_key(ciphertext, private_key, public_key):
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext
    s = mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    key = (c2 * s_inv) % p
    return key
