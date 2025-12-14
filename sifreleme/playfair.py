import string


def _clean_text(text: str) -> str:
    text = text.lower()
    text = text.replace("j", "i")
    return "".join(c for c in text if c.isalpha())


def _create_matrix(key: str):
    key = _clean_text(key)
    alphabet = string.ascii_lowercase.replace("j", "")
    seen = set()

    matrix = []

    for char in key + alphabet:
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    # 5x5 matris
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def _find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None


def _prepare_digrams(text: str):
    text = _clean_text(text)
    digrams = []
    i = 0

    while i < len(text):
        a = text[i]
        b = text[i + 1] if i + 1 < len(text) else "x"

        if a == b:
            digrams.append(a + "x")
            i += 1
        else:
            digrams.append(a + b)
            i += 2

    return digrams


def encrypt(text: str, key: str) -> str:
    matrix = _create_matrix(key)
    digrams = _prepare_digrams(text)
    result = ""

    for a, b in digrams:
        r1, c1 = _find_position(matrix, a)
        r2, c2 = _find_position(matrix, b)

        if r1 == r2:  # Aynı satır
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # Aynı sütun
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]
        else:  # Dikdörtgen
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def decrypt(text: str, key: str) -> str:
    matrix = _create_matrix(key)
    text = _clean_text(text)
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = _find_position(matrix, a)
        r2, c2 = _find_position(matrix, b)

        if r1 == r2:  # Aynı satır
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:  # Aynı sütun
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]
        else:  # Dikdörtgen
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result
