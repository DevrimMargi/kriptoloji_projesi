import socket
import os
from sifreleme.crypto_manager import encrypt_message, decrypt_message
from sifreleme.asymmetric.rsa_key_exchange import encrypt_sym_key # Daha önce düzelttiğimiz fonksiyon

HOST = "127.0.0.1"
PORT = 12345

def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[CLIENT] Sunucuya bağlandı.")

    # 1. ADIM: Sunucudan RSA Public Key'i al
    public_key_pem = sock.recv(2048)
    print("[CLIENT] RSA Public Key alındı.")

    while True:
        print("\n--- Yeni Mesaj ---")
        algorithm = input("Algoritma seç (AES, DES, AES (Manual), DES (Manual)): ")
        message = input("Mesaj (çıkmak için q): ")

        if message.lower() == "q":
            break

        # 2. ADIM: Algoritmaya göre rastgele anahtar üret (Ödev gereksinimi)
        # AES için 16 byte, DES için 8 byte
        if "AES" in algorithm:
            sym_key = os.urandom(16)
        elif "DES" in algorithm:
            sym_key = os.urandom(8)
        else:
            sym_key = input("Klasik şifreleme anahtarı girin: ").encode()

        # 3. ADIM: Simetrik anahtarı RSA ile şifrele (Sadece anahtar dağıtımı için)
        encrypted_key_b64 = encrypt_sym_key(sym_key, public_key_pem)

        # 4. ADIM: Mesajı simetrik anahtarla şifrele
        # crypto_manager bytes key beklediği için sym_key (bytes) gönderiyoruz
        encrypted_msg = encrypt_message(algorithm, message, sym_key)

        # 5. ADIM: Paketi oluştur ve gönder
        # Format: ALGORITMA | RSA_SIFRELI_ANAHTAR | SIFRELI_MESAJ
        packet = f"{algorithm}|{encrypted_key_b64}|{encrypted_msg}"
        sock.send(packet.encode("utf-8"))
        print(f"[CLIENT] Paket gönderildi. (RSA ile şifreli anahtar dahil)")

        # Sunucudan cevap (ACK) bekleme kısmı (opsiyonel)
        data = sock.recv(4096)
        if data:
            print("[SERVER]: Mesaj başarıyla alındı ve çözüldü.")

    sock.close()

if __name__ == "__main__":
    start_client()