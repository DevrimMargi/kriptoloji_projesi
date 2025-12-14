import socket

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
        # CLIENT'TAN MESAJ AL
        data = conn.recv(1024)
        if not data:
            print("[CLIENT AYRILDI]")
            break

        client_msg = data.decode("utf-8")
        print(f"[CLIENT] {client_msg}")

        # SERVER'DAN MESAJ GÖNDER
        server_msg = input("Server mesajı: ")
        conn.send(server_msg.encode("utf-8"))

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
