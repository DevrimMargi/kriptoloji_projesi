from sifreleme.caesar import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from sifreleme.vigenere import encrypt as vigenere_encrypt, decrypt as vigenere_decrypt
from sifreleme.affine import encrypt as affine_encrypt, decrypt as affine_decrypt
from sifreleme.playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt
from sifreleme.hill import encrypt as hill_encrypt, decrypt as hill_decrypt

# 🔐 KÜTÜPHANELİ (SİMETRİK)
from sifreleme.symmetric.aes_lib import encrypt as aes_encrypt, decrypt as aes_decrypt
from sifreleme.symmetric.des_lib import encrypt as des_encrypt, decrypt as des_decrypt

# 🔧 KÜTÜPHANESİZ (MANUAL)
from sifreleme.manual.manual_aes import encrypt as manual_aes_encrypt, decrypt as manual_aes_decrypt
from sifreleme.manual.manual_des import encrypt as manual_des_encrypt, decrypt as manual_des_decrypt


# --------------------------------------------------
# YARDIMCI FONKSİYON
# --------------------------------------------------

def normalize_key_for_classic(key):
    """
    Klasik şifrelemeler için:
    - key bytes ise string'e çevirir
    - key zaten string ise olduğu gibi bırakır
    """
    if isinstance(key, bytes):
        return key.decode("utf-8")
    return key


# --------------------------------------------------
# ENCRYPT MAP
# --------------------------------------------------

ENCRYPT_MAP = {
    # 🔐 KLASİK
    "Sezar": lambda msg, key: caesar_encrypt(
        msg,
        int(normalize_key_for_classic(key))
    ),

    "Vigenere": lambda msg, key: vigenere_encrypt(
        msg,
        normalize_key_for_classic(key)
    ),

    "Affine": lambda msg, key: affine_encrypt(
        msg,
        *map(int, normalize_key_for_classic(key).split(","))
    ),

    "Playfair": lambda msg, key: playfair_encrypt(
        msg,
        normalize_key_for_classic(key)
    ),

    "Hill": lambda msg, key: hill_encrypt(
        msg,
        [
            list(map(int, row.split(",")))
            for row in normalize_key_for_classic(key).split(";")
        ]
    ),

    # 🔐 KÜTÜPHANELİ (BYTES KEY)
    "AES": aes_encrypt,
    "DES": des_encrypt,

    # 🔧 MANUAL (BYTES KEY)
    "AES (Manual)": manual_aes_encrypt,
    "DES (Manual)": manual_des_encrypt,
}


# --------------------------------------------------
# DECRYPT MAP
# --------------------------------------------------

DECRYPT_MAP = {
    # 🔐 KLASİK
    "Sezar": lambda msg, key: caesar_decrypt(
        msg,
        int(normalize_key_for_classic(key))
    ),

    "Vigenere": lambda msg, key: vigenere_decrypt(
        msg,
        normalize_key_for_classic(key)
    ),

    "Affine": lambda msg, key: affine_decrypt(
        msg,
        *map(int, normalize_key_for_classic(key).split(","))
    ),

    "Playfair": lambda msg, key: playfair_decrypt(
        msg,
        normalize_key_for_classic(key)
    ),

    "Hill": lambda msg, key: hill_decrypt(
        msg,
        [
            list(map(int, row.split(",")))
            for row in normalize_key_for_classic(key).split(";")
        ]
    ),

    # 🔐 KÜTÜPHANELİ (BYTES KEY)
    "AES": aes_decrypt,
    "DES": des_decrypt,

    # 🔧 MANUAL (BYTES KEY)
    "AES (Manual)": manual_aes_decrypt,
    "DES (Manual)": manual_des_decrypt,
}


# --------------------------------------------------
# DIŞA AÇIK FONKSİYONLAR
# --------------------------------------------------

def encrypt_message(algorithm: str, message: str, key):
    if algorithm not in ENCRYPT_MAP:
        raise ValueError(f"Bilinmeyen algoritma: {algorithm}")

    return ENCRYPT_MAP[algorithm](message, key)


def decrypt_message(algorithm: str, message: str, key):
    if algorithm not in DECRYPT_MAP:
        raise ValueError(f"Bilinmeyen algoritma: {algorithm}")

    return DECRYPT_MAP[algorithm](message, key)
