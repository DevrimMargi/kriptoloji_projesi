from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os


KEY_SIZE = 2048


def generate_key_pair():
    """
    RSA public/private key üretir
    """
    key = RSA.generate(KEY_SIZE)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key


def encrypt_key_with_public(aes_key: str, public_key_bytes: bytes) -> str:
    """
    AES anahtarını RSA public key ile şifreler
    """
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)

    encrypted = cipher.encrypt(aes_key.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt_key_with_private(encrypted_key: str, private_key_bytes: bytes) -> str:
    """
    RSA private key ile AES anahtarını çözer
    """
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)

    decoded = base64.b64decode(encrypted_key)
    decrypted = cipher.decrypt(decoded)

    return decrypted.decode("utf-8")
