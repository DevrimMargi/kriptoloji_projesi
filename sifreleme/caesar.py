def encrypt(text: str, key: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('a')
            char_index = ord(char.lower()) - base
            new_index = (char_index + key) % 26
            result += chr(new_index + base)
        else:
            result += char
    return result


def decrypt(text: str, key: int) -> str:
    return encrypt(text, -key)
