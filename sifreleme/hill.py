def _clean_text(text: str) -> str:
         return "".join(c.lower() for c in text if c.isalpha())


def _mod_inverse(a: int, m: int) -> int:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("Modüler ters yok")


def _determinant_3x3(m):
    a, b, c = m[0]
    d, e, f = m[1]
    g, h, i = m[2]
    return (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26


def _matrix_mod_inv_3x3(m):
    det = _determinant_3x3(m)
    det_inv = _mod_inverse(det, 26)

    a, b, c = m[0]
    d, e, f = m[1]
    g, h, i = m[2]

    adj = [
        [(e*i - f*h), -(b*i - c*h),  (b*f - c*e)],
        [-(d*i - f*g), (a*i - c*g), -(a*f - c*d)],
        [(d*h - e*g), -(a*h - b*g),  (a*e - b*d)]
    ]

    return [[(adj[r][c] * det_inv) % 26 for c in range(3)] for r in range(3)]


def encrypt(text: str, key):
    text = _clean_text(text)

    while len(text) % 3 != 0:
        text += "x"

    result = ""

    for i in range(0, len(text), 3):
        block = [ord(text[i+j]) - ord('a') for j in range(3)]

        for row in range(3):
            val = sum(key[row][col] * block[col] for col in range(3)) % 26
            result += chr(val + ord('a'))

    return result


def decrypt(text: str, key):
    inv_key = _matrix_mod_inv_3x3(key)
    result = ""

    for i in range(0, len(text), 3):
        block = [ord(text[i+j]) - ord('a') for j in range(3)]

        for row in range(3):
            val = sum(inv_key[row][col] * block[col] for col in range(3)) % 26
            result += chr(val + ord('a'))

    return result
