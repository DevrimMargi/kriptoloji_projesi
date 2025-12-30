from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# -------------------------------------------------
# ECC KEY GENERATION
# -------------------------------------------------

def generate_ecc_keys():
    """
    ECC private / public key pair üretir (SECP256R1)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# -------------------------------------------------
# PUBLIC KEY SERIALIZATION
# -------------------------------------------------

def serialize_public_key(public_key):
    """
    Public key -> bytes (network üzerinden göndermek için)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data: bytes):
    """
    Bytes -> ECC public key (networkten geleni yüklemek için)
    """
    return serialization.load_pem_public_key(data)


# -------------------------------------------------
# ECDH + SESSION KEY DERIVATION
# -------------------------------------------------

def derive_session_key(private_key, peer_public_key, key_length: int = 16):
    """
    ECDH ile ortak sır üretir ve
    HKDF kullanarak AES / DES için session key türetir

    key_length:
        AES  -> 16 byte (default)
        DES  -> 8 byte
    """
    # ECDH ortak sır
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    # Ortak sırdan simetrik anahtar türet
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=b"ecc-ecdh-handshake",
    ).derive(shared_secret)

    return session_key


# -------------------------------------------------
# ALIAS (BACKWARD COMPATIBILITY)
# -------------------------------------------------

def derive_shared_key(private_key, peer_public_key, key_length: int = 16):
    """
    derive_session_key için alias.
    Akademik terminoloji uyumu ve geriye dönük kullanım için.
    """
    return derive_session_key(private_key, peer_public_key, key_length)
