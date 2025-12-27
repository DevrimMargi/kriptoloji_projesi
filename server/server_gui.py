import socket
import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import base64

from sifreleme.crypto_manager import encrypt_message, decrypt_message
from sifreleme.asymmetric.rsa_key_exchange import (
    generate_key_pair,
    decrypt_sym_key
)

HOST = "127.0.0.1"
PORT = 12345

# ---------------- SERVER GUI ----------------
class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Server")
        self.root.geometry("650x560")
        self.root.resizable(False, False)

        self.conn = None
        self.session_key = None  # AES / DES için (bytes)

        self.rsa_private_key = None
        self.rsa_public_key = None

        self.setup_ui()

    # ---------------- UI ----------------
    def setup_ui(self):
        ttk.Label(
            self.root,
            text="Python Secure Chat Server",
            font=("Segoe UI", 15, "bold")
        ).pack(pady=10)

        self.text_area = ScrolledText(
            self.root, width=75, height=18, font=("Consolas", 10)
        )
        self.text_area.pack(padx=10)
        self.text_area.config(state="disabled")

        control = ttk.Frame(self.root)
        control.pack(pady=10)

        ttk.Label(control, text="Algoritma:").grid(row=0, column=0, padx=5)

        self.algorithm = tk.StringVar(value="AES")
        ttk.Combobox(
            control,
            textvariable=self.algorithm,
            values=[
                "Sezar",
                "Vigenere",
                "Affine",
                "Playfair",
                "Hill",
                "AES",
                "DES",
            ],
            state="readonly",
            width=15
        ).grid(row=0, column=1, padx=5)

        ttk.Button(
            control,
            text="🚀 Server Başlat",
            command=self.start_server
        ).grid(row=0, column=2, padx=10)

        self.entry = ttk.Entry(self.root, width=60)
        self.entry.pack(pady=5)

        ttk.Button(
            self.root, text="📨 Gönder", command=self.send_message
        ).pack(pady=5)

    # ---------------- LOG ----------------
    def log(self, msg):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state="disabled")
        self.text_area.yview(tk.END)

    # ---------------- START SERVER ----------------
    def start_server(self):
        # 🔐 RSA anahtar çifti üret
        self.rsa_private_key, self.rsa_public_key = generate_key_pair()
        self.log("[RSA] RSA anahtar çifti üretildi (Server)")

        threading.Thread(
            target=self.server_thread,
            daemon=True
        ).start()

        self.log("[SUNUCU] Dinlemede: 127.0.0.1:12345")

    # ---------------- SERVER THREAD ----------------
    def server_thread(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)

        self.conn, addr = server_socket.accept()
        self.log(f"[BAĞLANTI] Client bağlandı: {addr}")

        # 🔐 RSA PUBLIC KEY → CLIENT
        public_key_b64 = base64.b64encode(self.rsa_public_key).decode("utf-8")
        self.conn.send(
            f"RSA_PUBLIC_KEY|{public_key_b64}".encode("utf-8")
        )
        self.log("[RSA] Public key client'a gönderildi")

        while True:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break

                parts = data.decode("utf-8").split("|")
                algorithm = parts[0]

                # 🔐 RSA KEY EXCHANGE (AES / DES)
                if algorithm == "KEY_EXCHANGE":
                    self.session_key = decrypt_sym_key(
                        parts[1],
                        self.rsa_private_key
                    )
                    self.log("[RSA] AES/DES session key alındı ve çözüldü")
                    continue

                # 🔓 KLASİK ALGORİTMALAR
                if algorithm in ["Sezar", "Vigenere", "Affine", "Playfair", "Hill"]:
                    key = parts[1]                 # string
                    encrypted_msg = parts[2]

                    decrypted = decrypt_message(
                        algorithm,
                        encrypted_msg,
                        key
                    )

                # 🔐 MODERN ALGORİTMALAR (AES / DES)
                else:
                    if not self.session_key:
                        self.log("[HATA] Session key yok, mesaj çözülemez")
                        continue

                    encrypted_msg = parts[1]

                    decrypted = decrypt_message(
                        algorithm,
                        encrypted_msg,
                        self.session_key
                    )

                self.log(f"\nCLIENT ({algorithm})")
                self.log(f"ŞİFRELİ : {encrypted_msg[:40]}...")
                self.log(f"ÇÖZÜLMÜŞ: {decrypted}")

            except Exception as e:
                self.log(f"[HATA] {e}")
                break

    # ---------------- SEND MESSAGE ----------------
    def send_message(self):
        if not self.conn:
            self.log("[HATA] Client bağlı değil")
            return

        message = self.entry.get().strip()
        if not message:
            return

        algo = self.algorithm.get()

        # 🔓 KLASİKLER
        if algo in ["Sezar", "Vigenere", "Affine", "Playfair", "Hill"]:
            self.log("[HATA] Server klasik algoritmalar için anahtar üretmez")
            return

        # 🔐 AES / DES
        if not self.session_key:
            self.log("[HATA] Session key yok")
            return

        encrypted = encrypt_message(algo, message, self.session_key)
        packet = f"{algo}|{encrypted}"
        self.conn.send(packet.encode("utf-8"))

        self.log(f"\nSen ({algo})")
        self.log(f"ŞİFRELİ : {encrypted[:40]}...")
        self.log(f"ASIL    : {message}")

        self.entry.delete(0, tk.END)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()
