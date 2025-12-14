def _clean_text(text: str) -> str:
         return "".join(c.lower() for c in text if c.isalpha())


def encrypt(text: str, key: str) -> str:
    text = _clean_text(text)
    key = _clean_text(key)

    if not key:
        raise ValueError("Anahtar boş olamaz")

    result = ""
    key_index = 0

    for char in text:
        t = ord(char) - ord('a')
        k = ord(key[key_index % len(key)]) - ord('a')
        c = (t + k) % 26
        result += chr(c + ord('a'))
        key_index += 1

    return result


def decrypt(text: str, key: str) -> str:
    key = _clean_text(key)

    if not key:
        raise ValueError("Anahtar boş olamaz")

    result = ""
    key_index = 0

    for char in text:
        t = ord(char) - ord('a')
        k = ord(key[key_index % len(key)]) - ord('a')
        p = (t - k) % 26
        result += chr(p + ord('a'))
        key_index += 1

    return result
