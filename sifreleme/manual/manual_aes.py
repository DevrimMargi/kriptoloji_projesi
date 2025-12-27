# ==============================
# SADELEŞTİRİLMİŞ MANUAL AES
# (EĞİTİM AMAÇLI - AES BENZERİ)
# ==============================

import base64


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def encrypt(message: str, key) -> str:
    """
    message : str
    key     : bytes veya str
    return  : base64 string
    """
    if isinstance(key, str):
        key = key.encode("utf-8")

    state = message.encode("utf-8")

    # 🔁 3 ROUND (sadeleştirilmiş)
    for _ in range(3):
        state = _xor_bytes(state, key)
        state = state[::-1]  # permutation

    # Ağ güvenliği için base64
    return base64.b64encode(state).decode("utf-8")


def decrypt(ciphertext: str, key) -> str:
    """
    ciphertext : base64 string
    key        : bytes veya str
    return     : plaintext
    """
    if isinstance(key, str):
        key = key.encode("utf-8")

    state = base64.b64decode(ciphertext)

    for _ in range(3):
        state = state[::-1]
        state = _xor_bytes(state, key)

    return state.decode("utf-8")
