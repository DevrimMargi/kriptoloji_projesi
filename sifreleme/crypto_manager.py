from sifreleme.caesar import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from sifreleme.vigenere import encrypt as vigenere_encrypt, decrypt as vigenere_decrypt
from sifreleme.affine import encrypt as affine_encrypt, decrypt as affine_decrypt
from sifreleme.playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt
from sifreleme.hill import encrypt as hill_encrypt, decrypt as hill_decrypt


def encrypt_message(algorithm, message, key):
    if algorithm == "Sezar":
        return caesar_encrypt(message, int(key))

    elif algorithm == "Vigenere":
        return vigenere_encrypt(message, key)

    elif algorithm == "Affine":
        a, b = map(int, key.split(","))
        return affine_encrypt(message, a, b)

    elif algorithm == "Playfair":
        return playfair_encrypt(message, key)

    elif algorithm == "Hill":
        rows = key.split(";")
        matrix = [list(map(int, row.split(","))) for row in rows]
        return hill_encrypt(message, matrix)

    else:
        raise ValueError("Bilinmeyen algoritma")


def decrypt_message(algorithm, message, key):
    if algorithm == "Sezar":
        return caesar_decrypt(message, int(key))

    elif algorithm == "Vigenere":
        return vigenere_decrypt(message, key)

    elif algorithm == "Affine":
        a, b = map(int, key.split(","))
        return affine_decrypt(message, a, b)

    elif algorithm == "Playfair":
        return playfair_decrypt(message, key)

    elif algorithm == "Hill":
        rows = key.split(";")
        matrix = [list(map(int, row.split(","))) for row in rows]
        return hill_decrypt(message, matrix)

    else:
        raise ValueError("Bilinmeyen algoritma")
