from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Ödev gereksinimi: RSA 2048-bit
KEY_SIZE = 2048

def generate_key_pair():
    """RSA 2048-bit anahtar çifti üretir."""
    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key() # PEM formatında
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_sym_key(sym_key: bytes, public_key_bytes: bytes) -> str:
    """
    AES (16 byte) veya DES (8 byte) anahtarını RSA Public Key ile şifreler.
    Çıktı: Base64 string (Ağ trafiğinde bozulmaması için).
    """
    # Güvenlik kontrolü: sym_key mutlaka bytes olmalı
    if isinstance(sym_key, str):
        sym_key = sym_key.encode("utf-8")

    # Public key'i içe aktar ve PKCS1_OAEP (Modern RSA Padding) kullan
    recipient_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    encrypted_data = cipher_rsa.encrypt(sym_key)
    return base64.b64encode(encrypted_data).decode("utf-8")

def decrypt_sym_key(encrypted_key_b64: str, private_key_bytes: bytes) -> bytes:
    """
    Şifreli anahtarı RSA Private Key ile çözer.
    Girdi: Base64 string -> Çıktı: bytes (AES/DES için hazır anahtar).
    """
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Base64'ten çöz ve RSA ile deşifre et
    encrypted_bytes = base64.b64decode(encrypted_key_b64)
    return cipher_rsa.decrypt(encrypted_bytes)