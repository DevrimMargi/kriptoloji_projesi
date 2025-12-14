# SADELEŞTİRİLMİŞ MANUAL DES (EĞİTİM AMAÇLI)

def _shift(text, shift):
    result = ""
    for ch in text:
        result += chr((ord(ch) + shift) % 256)
    return result


def encrypt(message: str, key: str) -> str:
    shift = len(key) % 8
    state = message

    # 2 ROUND (DES gibi)
    for _ in range(2):
        state = _shift(state, shift)
        state = state[::-1]

    return state


def decrypt(ciphertext: str, key: str) -> str:
    shift = len(key) % 8
    state = ciphertext

    for _ in range(2):
        state = state[::-1]
        state = _shift(state, -shift)

    return state
