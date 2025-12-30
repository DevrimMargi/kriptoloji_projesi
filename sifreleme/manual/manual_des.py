# =========================================================
# MANUAL DES IMPLEMENTATION (NO S-BOX)
# Educational / Academic Use Only
# =========================================================

import base64

# ---------------------------------------------------------
# DES TABLES
# ---------------------------------------------------------

IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

IP_INV = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
]

E = [
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
]

P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def permute(bits, table):
    return [bits[i - 1] for i in table]

def xor(a, b):
    return [i ^ j for i, j in zip(a, b)]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def bytes_to_bits(data):
    return [int(b) for byte in data for b in f"{byte:08b}"]

def bits_to_bytes(bits):
    return bytes(
        int("".join(map(str, bits[i:i+8])), 2)
        for i in range(0, len(bits), 8)
    )

# ---------------------------------------------------------
# KEY SCHEDULE
# ---------------------------------------------------------

def generate_keys(key_bytes):
    key_bits = bytes_to_bits(key_bytes)[:64]
    key = permute(key_bits, PC1)

    C, D = key[:28], key[28:]
    round_keys = []

    for shift in SHIFTS:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        round_keys.append(permute(C + D, PC2))

    return round_keys

# ---------------------------------------------------------
# FEISTEL FUNCTION (NO S-BOX)
# ---------------------------------------------------------

def feistel(R, key):
    expanded = permute(R, E)     # 32 → 48
    xored = xor(expanded, key)   # XOR with round key
    reduced = xored[:32]         # 48 → 32 (simple cut)
    return permute(reduced, P)   # P permutation

# ---------------------------------------------------------
# ENCRYPT
# ---------------------------------------------------------

def encrypt(message: str, key: bytes) -> str:
    data = message.encode("utf-8")
    data += b"\x00" * (8 - len(data) % 8)

    bits = bytes_to_bits(data)
    keys = generate_keys(key)
    encrypted_bits = []

    for i in range(0, len(bits), 64):
        block = permute(bits[i:i+64], IP)
        L, R = block[:32], block[32:]

        for k in keys:
            L, R = R, xor(L, feistel(R, k))

        encrypted_bits.extend(permute(R + L, IP_INV))

    return base64.b64encode(bits_to_bytes(encrypted_bits)).decode("utf-8")

# ---------------------------------------------------------
# DECRYPT
# ---------------------------------------------------------

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext_b64)
    bits = bytes_to_bits(raw)
    keys = generate_keys(key)[::-1]
    decrypted_bits = []

    for i in range(0, len(bits), 64):
        block = permute(bits[i:i+64], IP)
        L, R = block[:32], block[32:]

        for k in keys:
            L, R = R, xor(L, feistel(R, k))

        decrypted_bits.extend(permute(R + L, IP_INV))

    return bits_to_bytes(decrypted_bits).rstrip(b"\x00").decode("utf-8")

# ---------------------------------------------------------
# TEST
# ---------------------------------------------------------

if __name__ == "__main__":
    key = b"mysecret"      # 8 byte key
    message = "HELLO DES"

    cipher = encrypt(message, key)
    plain = decrypt(cipher, key)

    print("Encrypted:", cipher)
    print("Decrypted:", plain)
