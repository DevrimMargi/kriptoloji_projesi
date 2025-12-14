def _clean_text(text: str) -> str:
         return "".join(c.lower() for c in text if c.isalpha())


def _mod_inverse(a: int, m: int) -> int:
    """
    a'nın mod m'ye göre tersini bulur
    """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("a ve 26 aralarında asal değil, ters bulunamaz")


def encrypt(text: str, a: int, b: int) -> str:
    text = _clean_text(text)

    if a % 2 == 0 or a % 13 == 0:
        raise ValueError("a değeri 26 ile aralarında asal olmalıdır")

    result = ""

    for char in text:
        x = ord(char) - ord('a')
        c = (a * x + b) % 26
        result += chr(c + ord('a'))

    return result


def decrypt(text: str, a: int, b: int) -> str:
    a_inv = _mod_inverse(a, 26)
    result = ""

    for char in text:
        y = ord(char) - ord('a')
        p = (a_inv * (y - b)) % 26
        result += chr(p + ord('a'))

    return result
