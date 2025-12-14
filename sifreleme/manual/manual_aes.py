# SADELEŞTİRİLMİŞ MANUAL AES (EĞİTİM AMAÇLI)

def _xor(text, key):
    result = ""
    for i, ch in enumerate(text):
        result += chr(ord(ch) ^ ord(key[i % len(key)]))
    return result


def encrypt(message: str, key: str) -> str:
    state = message

    # 3 ROUND (sadeleştirilmiş)
    for _ in range(3):
        state = _xor(state, key)
        state = state[::-1]  # permutation

    return state


def decrypt(ciphertext: str, key: str) -> str:
    state = ciphertext

    for _ in range(3):
        state = state[::-1]
        state = _xor(state, key)

    return state
