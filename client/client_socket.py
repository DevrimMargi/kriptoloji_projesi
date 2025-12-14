import socket
from sifreleme.crypto_manager import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 12345


def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    print("[CLIENT] Server'a bağlandı")

    while True:
        algorithm = input("Algoritma seç (Sezar, Vigenere, AES, DES, vb): ")
        key = input("Anahtar: ")
        message = input("Mesaj (çıkmak için q): ")

        if message.lower() == "q":
            break

        encrypted = encrypt_message(algorithm, message, key)
        packet = f"{algorithm}|{key}|{encrypted}"

        sock.send(packet.encode("utf-8"))

        data = sock.recv(4096)
        algorithm, key, encrypted_reply = data.decode("utf-8").split("|", 2)

        decrypted_reply = decrypt_message(
            algorithm,
            encrypted_reply,
            key
        )

        print("\n[SERVER]")
        print("ŞİFRELİ :", encrypted_reply)
        print("ÇÖZÜLMÜŞ:", decrypted_reply)

    sock.close()


if __name__ == "__main__":
    start_client()
