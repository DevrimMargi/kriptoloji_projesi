import socket
from sifreleme.crypto_manager import decrypt_message, encrypt_message
from sifreleme.asymmetric.rsa_key_exchange import generate_key_pair, decrypt_sym_key

HOST = "127.0.0.1"
PORT = 12345

def start_server():
    # 1. ADIM: RSA Anahtar Çiftini Üret (Sadece sunucuda durur)
    print("[SERVER] RSA Anahtarları üretiliyor...")
    private_key_pem, public_key_pem = generate_key_pair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"[SERVER] Dinleniyor: {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    print(f"[CLIENT BAĞLANDI] {addr}")

    # 2. ADIM: Public Key'i İstemciye Gönder (Anahtar Dağıtımı Başlangıcı)
    conn.send(public_key_pem)
    print("[SERVER] RSA Public Key istemciye iletildi.")

    while True:
        data = conn.recv(4096)
        if not data:
            print("[CLIENT AYRILDI]")
            break

        packet = data.decode("utf-8")

        try:
            # Paket yapısı: ALGORITMA | RSA_SIFRELI_KEY | SIFRELI_MESAJ
            algorithm, enc_key_b64, encrypted_msg = packet.split("|", 2)

            # 3. ADIM: RSA Private Key ile Simetrik Anahtarı Çöz
            # Bu işlem sadece anahtar iletiminde 1 kez yapılır, ancak akışın sürekliliği için her pakette çözüyoruz
            sym_key = decrypt_sym_key(enc_key_b64, private_key_pem)

            # 4. ADIM: Çözülen Simetrik Anahtar ile Mesajı Deşifre Et
            decrypted_msg = decrypt_message(
                algorithm,
                encrypted_msg,
                sym_key # Artık RSA ile çözülmüş orijinal AES/DES anahtarı
            )

            print(f"\n[CLIENT] Algoritma: {algorithm}")
            print("RSA Şifreli Anahtar (Base64):", enc_key_b64[:32], "...")
            print("ŞİFRELİ MESAJ :", encrypted_msg)
            print("ÇÖZÜLMÜŞ METİN:", decrypted_msg)

            # -------- SERVER CEVABI (ACK) --------
            reply = f"Mesajiniz alindi ({algorithm})"
            
            # Cevabı da aynı anahtarla şifreleyerek geri gönderiyoruz
            encrypted_reply = encrypt_message(algorithm, reply, sym_key)
            
            # Sunucu cevabında anahtarı tekrar göndermeye gerek yok (İstemci zaten biliyor)
            # Ancak akış birliğini korumak için benzer yapıda dönebilirsiniz
            reply_packet = f"{algorithm}|ACK|{encrypted_reply}"
            conn.send(reply_packet.encode("utf-8"))

        except Exception as e:
            print("[HATA] Paket işlenemedi:", e)
            continue

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()