import socket
import time

from sifreleme.crypto_manager import decrypt_message, encrypt_message
from sifreleme.asymmetric.rsa_key_exchange import generate_key_pair, decrypt_sym_key

HOST = "127.0.0.1"
PORT = 12345


def start_server():
    # 1. ADIM: RSA Anahtar Çifti
    print("[SERVER] RSA Anahtarları üretiliyor...")
    private_key_pem, public_key_pem = generate_key_pair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"[SERVER] Dinleniyor: {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    print(f"[CLIENT BAĞLANDI] {addr}")

    # 2. ADIM: RSA Public Key gönder
    conn.send(public_key_pem)
    print("[SERVER] RSA Public Key istemciye iletildi.")

    while True:
        data = conn.recv(4096)
        if not data:
            print("[CLIENT AYRILDI]")
            break

        receive_time = time.time()
        packet = data.decode("utf-8")

        try:
            # Paket:
            # ALGORITHM | RSA_KEY | ENCRYPTED_MSG | (OPSİYONEL) SEND_TIME
            parts = packet.split("|")

            algorithm = parts[0]
            enc_key_b64 = parts[1]
            encrypted_msg = parts[2]

            send_time = None
            if len(parts) >= 4:
                try:
                    send_time = float(parts[3])
                except:
                    send_time = None

            # ⏱ Network Delay
            if send_time:
                network_delay = receive_time - send_time
                print(f"[TIMING] Ağ Gecikmesi: {network_delay:.6f} saniye")

            # 3. ADIM: RSA ile simetrik anahtarı çöz
            sym_key = decrypt_sym_key(enc_key_b64, private_key_pem)

            # 4. ADIM: Mesajı çöz (⏱ süre ölçümü)
            start_dec = time.time()

            decrypted_msg = decrypt_message(
                algorithm,
                encrypted_msg,
                sym_key
            )

            end_dec = time.time()
            decryption_time = end_dec - start_dec

            print(f"[TIMING] Çözme Süresi: {decryption_time:.6f} saniye")

            # ⏱ Toplam süre (network varsa dahil)
            if send_time:
                total_time = network_delay + decryption_time
                print(f"[TIMING] Toplam Süre: {total_time:.6f} saniye")

            print(f"\n[CLIENT] Algoritma: {algorithm}")
            print("RSA Şifreli Anahtar:", enc_key_b64[:32], "...")
            print("ŞİFRELİ MESAJ :", encrypted_msg[:60], "...")
            print("ÇÖZÜLMÜŞ METİN:", decrypted_msg)

            # -------- SERVER CEVABI (ACK) --------
            reply = f"Mesajiniz alindi ({algorithm})"
            encrypted_reply = encrypt_message(algorithm, reply, sym_key)

            reply_packet = f"{algorithm}|ACK|{encrypted_reply}"
            conn.send(reply_packet.encode("utf-8"))

        except Exception as e:
            print("[HATA] Paket işlenemedi:", e)
            continue

    conn.close()
    server_socket.close()


if __name__ == "__main__":
    start_server()
