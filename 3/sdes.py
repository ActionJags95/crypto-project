import random
from collections import defaultdict

# Permutation functions
def permute(bits, order):
    return [bits[i] for i in order]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def split(bits):
    return bits[:len(bits)//2], bits[len(bits)//2:]

# S-boxes
SBOX = {
    0: [[1, 0], [3, 2]],
    1: [[3, 2], [1, 0]]
}

def sbox_lookup(sbox_num, bits):
    row = bits[0]
    col = bits[1]
    val = SBOX[sbox_num][row][col]
    return [val >> 1 & 1, val & 1]

# Key generation for 3 rounds (10-bit key)
def generate_keys(key):
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    P8  = [5, 2, 6, 3, 7, 4, 9, 8]
    key = permute(key, P10)

    def left_shift(bits, shifts):
        return bits[shifts:] + bits[:shifts]

    L, R = split(key)
    K = []
    for i in range(1, 4):  # 3 subkeys
        L = left_shift(L, i)
        R = left_shift(R, i)
        K.append(permute(L + R, P8))
    return K

# Initial and final permutation
IP = [1, 5, 2, 0, 3, 7, 4, 6]
IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
P4 = [1, 3, 2, 0]

# Feistel function
def F(R, K):
    R_expanded = permute(R, EP)
    xor_result = xor(R_expanded, K)
    L1, L2 = split(xor_result)
    sbox_out = sbox_lookup(0, L1) + sbox_lookup(1, L2)
    return permute(sbox_out, P4)

# One round of S-DES
def round_sd(left, right, subkey):
    return right, xor(left, F(right, subkey))

# 3-round S-DES encryption
def sdes_encrypt(plaintext_bits, keys):
    bits = permute(plaintext_bits, IP)
    L, R = split(bits)
    for key in keys:
        L, R = round_sd(L, R, key)
    cipher = permute(R + L, IP_INV)  # Note the swap before IP^-1
    return cipher

# Generate bit list from int
def int_to_bits(x, size=8):
    return [int(b) for b in format(x, f'0{size}b')]

def bits_to_int(bits):
    return int(''.join(str(b) for b in bits), 2)

# Differential Cryptanalysis
def differential_attack(key_guess_range=256):
    input_diff = int_to_bits(0b00001111)
    key_counts = defaultdict(int)
    key = [random.randint(0, 1) for _ in range(10)]
    keys = generate_keys(key)

    for _ in range(1000):  # Chosen plaintexts
        p1 = random.randint(0, 255)
        p2 = p1 ^ input_diff
        c1 = sdes_encrypt(int_to_bits(p1), keys)
        c2 = sdes_encrypt(int_to_bits(p2), keys)
        delta_c = xor(c1, c2)

        # Try all possible subkey guesses for last round
        for guess in range(key_guess_range):
            guess_bits = int_to_bits(guess, 8)
            # Simulate inverse of last round (just a heuristic here)
            if delta_c[:4] == guess_bits[:4]:
                key_counts[guess] += 1

    best_guess = max(key_counts, key=key_counts.get)
    print(f"Most probable last subkey: {format(best_guess, '08b')} (score: {key_counts[best_guess]})")
    return best_guess

# Run the attack
if __name__ == "__main__":
    differential_attack()
