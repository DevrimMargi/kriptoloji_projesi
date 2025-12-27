import base64

# ÖDEV ŞARTI: S-Box kullanımı
S_BOX = [
    [0x9, 0x4, 0xa, 0xb],
    [0xd, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xc, 0xe, 0xf, 0x7]
]

S_BOX_INVERSE = [
    [0xa, 0x5, 0x9, 0xb],
    [0x1, 0x7, 0x8, 0xf],
    [0x6, 0x0, 0x2, 0x3],
    [0xc, 0x4, 0xd, 0xe]
]

def sub_nibbles(state, box):
    for i in range(len(state)):
        for j in range(len(state[i])):
            high = (state[i][j] >> 2) & 0b11
            low = state[i][j] & 0b11
            state[i][j] = box[high][low]
    return state

# ÖDEV ŞARTI: Permütasyon (ShiftRows)
def shift_rows(state):
    for i in range(len(state)):
        state[i] = state[i][i:] + state[i][:i]
    return state

def shift_rows_inverse(state):
    for i in range(len(state)):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def add_round_key(state, key_int):
    # State matrisini (2x2) 16-bit block'a çevirip XOR'lar
    block = 0
    block |= state[0][0] << 12 | state[0][1] << 8 | state[1][0] << 4 | state[1][1]
    block ^= key_int
    
    # Tekrar matrise çevir
    new_state = [[0, 0], [0, 0]]
    new_state[0][0] = (block & 0xF000) >> 12
    new_state[0][1] = (block & 0x0F00) >> 8
    new_state[1][0] = (block & 0x00F0) >> 4
    new_state[1][1] = block & 0x000F
    return new_state

def encrypt(message: str, key: bytes) -> str:
    """Kütüphanesiz Manuel Şifreleme (Ödev Mod 2)"""
    # Anahtarın ilk 2 byte'ını 16-bit integer'a çevir (S-AES gereği)
    key_int = int.from_bytes(key[:2], 'big')
    
    # Mesajı 2 byte'lık bloklara bölerek şifrele
    msg_bytes = message.encode('utf-8')
    if len(msg_bytes) % 2 != 0: msg_bytes += b'\x00' # Padding
    
    encrypted_bytes = bytearray()
    for i in range(0, len(msg_bytes), 2):
        block = int.from_bytes(msg_bytes[i:i+2], 'big')
        
        # --- ŞİFRELEME ROUNDLARI ---
        state = [[(block & 0xF000) >> 12, (block & 0x0F00) >> 8],
                 [(block & 0x00F0) >> 4,  block & 0x000F]]
        
        state = add_round_key(state, key_int) # Pre-round
        state = sub_nibbles(state, S_BOX)     # Round 1
        state = shift_rows(state)
        state = add_round_key(state, key_int) # Round 2
        
        # Matrisi tekrar 2 byte'a çevir
        res = (state[0][0] << 12 | state[0][1] << 8 | state[1][0] << 4 | state[1][1])
        encrypted_bytes.extend(res.to_bytes(2, 'big'))
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt(ciphertext: str, key: bytes) -> str:
    key_int = int.from_bytes(key[:2], 'big')
    data = base64.b64decode(ciphertext)
    decrypted_bytes = bytearray()
    
    for i in range(0, len(data), 2):
        block = int.from_bytes(data[i:i+2], 'big')
        state = [[(block & 0xF000) >> 12, (block & 0x0F00) >> 8],
                 [(block & 0x00F0) >> 4,  block & 0x000F]]
        
        state = add_round_key(state, key_int)
        state = shift_rows_inverse(state)
        state = sub_nibbles(state, S_BOX_INVERSE)
        state = add_round_key(state, key_int)
        
        res = (state[0][0] << 12 | state[0][1] << 8 | state[1][0] << 4 | state[1][1])
        decrypted_bytes.extend(res.to_bytes(2, 'big'))
        
    return decrypted_bytes.decode('utf-8').rstrip('\x00')