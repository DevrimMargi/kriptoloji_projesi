import base64
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
# YARDIMCI FONKSİYONLAR
# --------------------------------------------------

def normalize_key_for_classic(key):
    """Klasik şifrelemeler için key'i string'e hazırlar."""
    if isinstance(key, bytes):
        return key.decode("utf-8")
    return str(key)

def ensure_bytes(data):
    """Verinin bytes formatında olduğundan emin olur."""
    if isinstance(data, str):
        return data.encode("utf-8")
    return data

# --------------------------------------------------
# ENCRYPT MAP
# --------------------------------------------------

ENCRYPT_MAP = {
    # 🔐 KLASİK
    "Sezar": lambda msg, key: caesar_encrypt(msg, int(normalize_key_for_classic(key))),
    "Vigenere": lambda msg, key: vigenere_encrypt(msg, normalize_key_for_classic(key)),
    "Affine": lambda msg, key: affine_encrypt(msg, *map(int, normalize_key_for_classic(key).split(","))),
    "Playfair": lambda msg, key: playfair_encrypt(msg, normalize_key_for_classic(key)),
    "Hill": lambda msg, key: hill_encrypt(msg, [list(map(int, r.split(","))) for r in normalize_key_for_classic(key).split(";")]),

    # 🔐 KÜTÜPHANELİ (Otomatik padding ve bytes yönetimi eklenmeli)
    "AES": lambda msg, key: aes_encrypt(msg, ensure_bytes(key)),
    "DES": lambda msg, key: des_encrypt(msg, ensure_bytes(key)),

    # 🔧 MANUAL (Round ve S-Box yapılarını kullanacak fonksiyonlar)
    "AES (Manual)": lambda msg, key: manual_aes_encrypt(msg, ensure_bytes(key)),
    "DES (Manual)": lambda msg, key: manual_des_encrypt(msg, ensure_bytes(key)),
}

# --------------------------------------------------
# DECRYPT MAP
# --------------------------------------------------

DECRYPT_MAP = {
    "Sezar": lambda msg, key: caesar_decrypt(msg, int(normalize_key_for_classic(key))),
    "Vigenere": lambda msg, key: vigenere_decrypt(msg, normalize_key_for_classic(key)),
    "Affine": lambda msg, key: affine_decrypt(msg, *map(int, normalize_key_for_classic(key).split(","))),
    "Playfair": lambda msg, key: playfair_decrypt(msg, normalize_key_for_classic(key)),
    "Hill": lambda msg, key: hill_decrypt(msg, [list(map(int, r.split(","))) for r in normalize_key_for_classic(key).split(";")]),

    "AES": lambda msg, key: aes_decrypt(msg, ensure_bytes(key)),
    "DES": lambda msg, key: des_decrypt(msg, ensure_bytes(key)),

    "AES (Manual)": lambda msg, key: manual_aes_decrypt(msg, ensure_bytes(key)),
    "DES (Manual)": lambda msg, key: manual_des_decrypt(msg, ensure_bytes(key)),
}

# --------------------------------------------------
# DIŞA AÇIK FONKSİYONLAR
# --------------------------------------------------

def encrypt_message(algorithm: str, message: str, key):
    if algorithm not in ENCRYPT_MAP:
        raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    # Çıktının her zaman string/base64 olması Wireshark analizi için kritiktir
    result = ENCRYPT_MAP[algorithm](message, key)
    return result if isinstance(result, str) else base64.b64encode(result).decode("utf-8")

def decrypt_message(algorithm: str, message: str, key):
    if algorithm not in DECRYPT_MAP:
        raise ValueError(f"Bilinmeyen algoritma: {algorithm}")
    
    # Eğer mesaj Base64 ise önce decode edilebilir (Algoritma içine de gömülebilir)
    return DECRYPT_MAP[algorithm](message, key)