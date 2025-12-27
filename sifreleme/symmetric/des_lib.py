from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

BLOCK_SIZE = 8  # DES → 8 byte


def _format_key(key) -> bytes:
    """
    DES anahtarı 8 byte olmak zorunda.
    key hem str hem bytes olabilir.
    """
    if isinstance(key, bytes):
        key_bytes = key
    else:
        key_bytes = key.encode("utf-8")

    # DES için 8 byte'a sabitle
    return key_bytes.ljust(BLOCK_SIZE, b"\0")[:BLOCK_SIZE]


def encrypt(message: str, key) -> str:
    key_bytes = _format_key(key)

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    ciphertext = cipher.encrypt(
        pad(message.encode("utf-8"), BLOCK_SIZE)
    )

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt(ciphertext: str, key) -> str:
    key_bytes = _format_key(key)

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decoded = base64.b64decode(ciphertext)

    plaintext = unpad(cipher.decrypt(decoded), BLOCK_SIZE)
    return plaintext.decode("utf-8")
