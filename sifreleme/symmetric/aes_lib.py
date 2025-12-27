from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

BLOCK_SIZE = 16  # AES-128 → 16 byte


def _format_key(key) -> bytes:
    """
    AES anahtarı 16 byte olmak zorunda.
    key hem str hem bytes olabilir.
    """
    if isinstance(key, bytes):
        key_bytes = key
    else:
        key_bytes = key.encode("utf-8")

    # 16 byte'a sabitle
    return key_bytes.ljust(BLOCK_SIZE, b"\0")[:BLOCK_SIZE]


def encrypt(message: str, key) -> str:
    key_bytes = _format_key(key)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = cipher.encrypt(
        pad(message.encode("utf-8"), BLOCK_SIZE)
    )

    # Ağ üzerinden güvenli taşımak için base64
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt(ciphertext: str, key) -> str:
    key_bytes = _format_key(key)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decoded = base64.b64decode(ciphertext)

    plaintext = unpad(cipher.decrypt(decoded), BLOCK_SIZE)
    return plaintext.decode("utf-8")
