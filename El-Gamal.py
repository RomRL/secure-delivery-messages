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
def generate_keypair():
    # Generate large prime numbers p and g
    p = generate_prime(256)
    g = random.randint(2, p - 2)

    # Generate private key x
    x = random.randint(2, p - 2)

    # Calculate public key y
    y = mod_exp(g, x, p)

    return (p, g, y), x

# Encrypt key (message)
def encrypt_key(key, public_key):
    p, g, y = public_key
    k = random.randint(2, p - 2)
    c1 = mod_exp(g, k, p)
    s = mod_exp(y, k, p)
    c2 = (s * key) % p
    return (c1, c2)

# Decrypt key (message)
def decrypt_key(ciphertext, private_key, public_key):
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext
    s = mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    key = (c2 * s_inv) % p
    return key


public_key, private_key = generate_keypair()
key_to_transport = 12345
print("Original key:", key_to_transport)

ciphertext = encrypt_key(key_to_transport, public_key)
print("Encrypted key:", ciphertext)

decrypted_key = decrypt_key(ciphertext, private_key, public_key)
print("Decrypted key:", decrypted_key)

"""
the Seconed code:

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
def generate_keypair():
    # Generate large prime numbers p and g
    p = generate_prime(256)
    g = random.randint(2, p - 2)

    # Generate private key x
    x = random.randint(2, p - 2)

    # Calculate public key y
    y = mod_exp(g, x, p)

    return (p, g, y), x

# Encrypt message
def encrypt_message(message, public_key):
    p, g, y = public_key
    k = random.randint(2, p - 2)
    c1 = mod_exp(g, k, p)
    s = mod_exp(y, k, p)
    c2 = [(s * ord(char)) % p for char in message]
    return (c1, c2)

# Decrypt message
def decrypt_message(ciphertext, private_key, public_key):
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext
    s = mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    decrypted_message = ''.join([chr((char * s_inv) % p) for char in c2])
    return decrypted_message

# Alice and Bob exchange keys
alice_public_key, alice_private_key = generate_keypair()
bob_public_key, bob_private_key = generate_keypair()

# Alice encrypts a message for Bob
message_to_bob = "Hello Bob!"
encrypted_message_to_bob = encrypt_message(message_to_bob, bob_public_key)

# Bob decrypts the message from Alice
decrypted_message_from_alice = decrypt_message(encrypted_message_to_bob, bob_private_key, bob_public_key)
print("Bob's decrypted message from Alice:", decrypted_message_from_alice)

# Bob encrypts a message for Alice
message_to_alice = "Hello Alice!"
encrypted_message_to_alice = encrypt_message(message_to_alice, alice_public_key)

# Alice decrypts the message from Bob
decrypted_message_from_bob = decrypt_message(encrypted_message_to_alice, alice_private_key, alice_public_key)
print("Alice's decrypted message from Bob:", decrypted_message_from_bob)

"""