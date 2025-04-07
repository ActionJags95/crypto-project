import hashlib
import random

# Step 1: Generate large prime numbers
def is_prime(n, k=5):  # k = number of test rounds
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Ensure it's odd and has highest bit set
        if is_prime(p):
            return p


# Step 2: Compute GCD and modular inverse
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    # Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Step 3: Modular exponentiation
def modexp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Step 4: RSA key generation
def generate_keys():
    p = generate_large_prime(512)
    q = generate_large_prime(512)
    while q == p:
        q = generate_large_prime(512)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = modinv(e, phi)
    return (e, n), (d, n)

# Step 5: Hash message using SHA-256 (std lib)
def sha256_hash(message):
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

# Step 6: Sign hash using private key
def sign(message, private_key):
    hashed = sha256_hash(message)
    d, n = private_key
    return modexp(hashed, d, n)

# Step 7: Verify signature using public key
def verify(message, signature, public_key):
    hashed = sha256_hash(message)
    e, n = public_key
    decrypted_hash = modexp(signature, e, n)
    return hashed == decrypted_hash

# 🔐 Main Execution
public_key, private_key = generate_keys()
message = "Secure communication using manual RSA!"

signature = sign(message, private_key)
print("🔏 Signature:", signature)

valid = verify(message, signature, public_key)
print("✅ Valid Signature:" if valid else "❌ Invalid Signature")

message = "Hello"

valid = verify(message, signature, public_key)
print("✅ Valid Signature:" if valid else "❌ Invalid Signature")
