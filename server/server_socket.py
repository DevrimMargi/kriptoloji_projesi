import socket
from sifreleme.crypto_manager import decrypt_message, encrypt_message

HOST = "127.0.0.1"
PORT = 12345


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    print(f"[SERVER] Dinleniyor: {HOST}:{PORT}")

    conn, addr = server_socket.accept()
    print(f"[CLIENT BAĞLANDI] {addr}")

    while True:
        data = conn.recv(4096)
        if not data:
            print("[CLIENT AYRILDI]")
            break

        packet = data.decode("utf-8")

        try:
            algorithm, key, encrypted_msg = packet.split("|", 2)

            decrypted_msg = decrypt_message(
                algorithm,
                encrypted_msg,
                key
            )

            print(f"\n[CLIENT] ({algorithm})")
            print("ŞİFRELİ :", encrypted_msg)
            print("ÇÖZÜLMÜŞ:", decrypted_msg)

        except Exception as e:
            print("[HATA] Mesaj çözülemedi:", e)
            continue

        # -------- SERVER CEVABI --------
        reply = input("Server mesajı: ")

        encrypted_reply = encrypt_message(
            algorithm,
            reply,
            key
        )

        reply_packet = f"{algorithm}|{key}|{encrypted_reply}"
        conn.send(reply_packet.encode("utf-8"))

    conn.close()
    server_socket.close()


if __name__ == "__main__":
    start_server()
