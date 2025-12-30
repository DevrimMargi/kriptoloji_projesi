import base64

# =====================================================
# MANUAL BLOCK CIPHER (NO S-BOX)
# Educational / Academic Purpose Only
# =====================================================

# -----------------------------------------------------
# PERMUTATION (ShiftRows)
# -----------------------------------------------------

def shift_rows(state):
    for i in range(len(state)):
        state[i] = state[i][i:] + state[i][:i]
    return state

def shift_rows_inverse(state):
    for i in range(len(state)):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

# -----------------------------------------------------
# ADD ROUND KEY
# -----------------------------------------------------

def add_round_key(state, key_int):
    block = 0
    block |= state[0][0] << 12
    block |= state[0][1] << 8
    block |= state[1][0] << 4
    block |= state[1][1]

    block ^= key_int

    new_state = [[0, 0], [0, 0]]
    new_state[0][0] = (block >> 12) & 0xF
    new_state[0][1] = (block >> 8) & 0xF
    new_state[1][0] = (block >> 4) & 0xF
    new_state[1][1] = block & 0xF

    return new_state

# -----------------------------------------------------
# ENCRYPT
# -----------------------------------------------------

def encrypt(message: str, key: bytes) -> str:
    key_int = int.from_bytes(key[:2], "big")

    msg_bytes = message.encode("utf-8")
    if len(msg_bytes) % 2 != 0:
        msg_bytes += b"\x00"

    encrypted = bytearray()

    for i in range(0, len(msg_bytes), 2):
        block = int.from_bytes(msg_bytes[i:i+2], "big")

        state = [
            [(block >> 12) & 0xF, (block >> 8) & 0xF],
            [(block >> 4) & 0xF, block & 0xF]
        ]

        # Round 1
        state = add_round_key(state, key_int)
        state = shift_rows(state)

        # Round 2
        state = add_round_key(state, key_int)

        result = (
            (state[0][0] << 12) |
            (state[0][1] << 8)  |
            (state[1][0] << 4)  |
            state[1][1]
        )

        encrypted.extend(result.to_bytes(2, "big"))

    return base64.b64encode(encrypted).decode("utf-8")

# -----------------------------------------------------
# DECRYPT
# -----------------------------------------------------

def decrypt(ciphertext: str, key: bytes) -> str:
    key_int = int.from_bytes(key[:2], "big")
    data = base64.b64decode(ciphertext)

    decrypted = bytearray()

    for i in range(0, len(data), 2):
        block = int.from_bytes(data[i:i+2], "big")

        state = [
            [(block >> 12) & 0xF, (block >> 8) & 0xF],
            [(block >> 4) & 0xF, block & 0xF]
        ]

        # Reverse Round 2
        state = add_round_key(state, key_int)

        # Reverse Round 1
        state = shift_rows_inverse(state)
        state = add_round_key(state, key_int)

        result = (
            (state[0][0] << 12) |
            (state[0][1] << 8)  |
            (state[1][0] << 4)  |
            state[1][1]
        )

        decrypted.extend(result.to_bytes(2, "big"))

    return decrypted.decode("utf-8").rstrip("\x00")

# -----------------------------------------------------
# TEST
# -----------------------------------------------------

if __name__ == "__main__":
    key = b"AB"
    msg = "HELLO"

    c = encrypt(msg, key)
    p = decrypt(c, key)

    print("Encrypted:", c)
    print("Decrypted:", p)
