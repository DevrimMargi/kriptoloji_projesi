from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


BLOCK_SIZE = 16  # AES-128 → 16 byte


def _format_key(key: str) -> bytes:
    """
    Kullanıcının girdiği anahtarı 16 byte'a sabitler
    """
    key_bytes = key.encode("utf-8")
    return key_bytes.ljust(BLOCK_SIZE, b"\0")[:BLOCK_SIZE]


def encrypt(message: str, key: str) -> str:
    key_bytes = _format_key(key)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode("utf-8"), BLOCK_SIZE))

    # Ağ üzerinden güvenli taşımak için base64
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt(ciphertext: str, key: str) -> str:
    key_bytes = _format_key(key)

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decoded = base64.b64decode(ciphertext)

    plaintext = unpad(cipher.decrypt(decoded), BLOCK_SIZE)
    return plaintext.decode("utf-8")
