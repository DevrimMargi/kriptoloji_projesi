import socket
import os
import time

from sifreleme.crypto_manager import encrypt_message
from sifreleme.asymmetric.rsa_key_exchange import encrypt_sym_key

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

        # 2. ADIM: Algoritmaya göre anahtar üret
        if "AES" in algorithm:
            sym_key = os.urandom(16)
        elif "DES" in algorithm:
            sym_key = os.urandom(8)
        else:
            sym_key = input("Klasik şifreleme anahtarı girin: ").encode()

        # 3. ADIM: Simetrik anahtarı RSA ile şifrele
        encrypted_key_b64 = encrypt_sym_key(sym_key, public_key_pem)

        # 4. ADIM: MESAJI ŞİFRELE (⏱️ SÜRE ÖLÇÜMÜ)
        start_enc = time.time()
        encrypted_msg = encrypt_message(algorithm, message, sym_key)
        end_enc = time.time()

        encryption_time = end_enc - start_enc
        print(f"[TIMING] Şifreleme Süresi: {encryption_time:.6f} saniye")

        # 5. ADIM: Gönderme zamanını al
        send_time = time.time()

        # 6. ADIM: Paketi oluştur
        # Format:
        # ALGORITHM | RSA_KEY | ENCRYPTED_MSG | SEND_TIME
        packet = f"{algorithm}|{encrypted_key_b64}|{encrypted_msg}|{send_time}"

        sock.send(packet.encode("utf-8"))
        print("[CLIENT] Paket gönderildi.")

        # Sunucudan ACK
        data = sock.recv(4096)
        if data:
            print("[SERVER]: Mesaj başarıyla alındı ve çözüldü.")

    sock.close()

if __name__ == "__main__":
    start_client()
