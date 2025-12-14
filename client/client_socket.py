import socket

HOST = "127.0.0.1"
PORT = 12345

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    print(f"[CLIENT] Server'a bağlandı: {HOST}:{PORT}")

    while True:
        msg = input("Mesaj gir (çıkmak için q): ")

        if msg.lower() == "q":
            break

        # CLIENT → SERVER
        client_socket.send(msg.encode("utf-8"))

        # SERVER → CLIENT
        data = client_socket.recv(1024)
        server_msg = data.decode("utf-8")
        print(f"[SERVER] {server_msg}")

    client_socket.close()

if __name__ == "__main__":
    start_client()
