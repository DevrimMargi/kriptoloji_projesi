import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import socket
import threading
import base64
import os
import random
import string

# ---- proje içi modüller ----
from sifreleme.crypto_manager import encrypt_message, decrypt_message
from sifreleme.asymmetric.rsa_key_exchange import encrypt_sym_key

HOST = "127.0.0.1"
PORT = 12345


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Client")
        self.root.geometry("650x560")
        self.root.resizable(False, False)

        self.client_socket = None
        self.session_key = None            # aktif anahtar
        self.server_rsa_public_key = None
        self.key_sent = False              # AES/DES için RSA key exchange yapıldı mı

        self.setup_ui()

    # ---------------- UI ----------------
    def setup_ui(self):
        ttk.Label(
            self.root,
            text="Python Secure Chat Client",
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

        self.algorithm = tk.StringVar(value="Sezar")
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
            text="🔐 Anahtar Oluştur",
            command=self.generate_key
        ).grid(row=0, column=2, padx=10)

        self.entry = ttk.Entry(self.root, width=60)
        self.entry.pack(pady=5)

        btns = ttk.Frame(self.root)
        btns.pack(pady=5)

        ttk.Button(btns, text="📨 Gönder", command=self.send_message).grid(row=0, column=0, padx=5)
        ttk.Button(btns, text="🔌 Server'a Bağlan", command=self.connect).grid(row=0, column=1, padx=5)

    # ---------------- LOG ----------------
    def log(self, msg):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.config(state="disabled")
        self.text_area.yview(tk.END)

    # ---------------- CONNECT ----------------
    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.log("Server'a bağlandın.")

            threading.Thread(
                target=self.listen_server,
                daemon=True
            ).start()

        except Exception as e:
            self.log(f"[HATA] {e}")

    # ---------------- KEY GENERATION ----------------
    def generate_key(self):
        algo = self.algorithm.get()
        self.key_sent = False

        # 🔓 KLASİK ALGORİTMALAR
        if algo == "Sezar":
            self.session_key = str(random.randint(1, 25))

        elif algo == "Vigenere":
            self.session_key = ''.join(random.choices(string.ascii_uppercase, k=6))

        elif algo == "Affine":
            a = random.choice([3, 5, 7, 11, 17, 19, 23, 25])
            b = random.randint(0, 25)
            self.session_key = f"{a},{b}"

        elif algo == "Playfair":
            self.session_key = ''.join(
                random.sample("ABCDEFGHIKLMNOPQRSTUVWXYZ", 5)
            )

        elif algo == "Hill":
            self.session_key = "2,3;1,4"

        # 🔐 MODERN ALGORİTMALAR (AES / DES)
        elif algo in ["AES", "DES"]:
            self.session_key = os.urandom(16 if algo == "AES" else 8)

            if not self.server_rsa_public_key:
                self.log("[HATA] RSA public key henüz alınmadı")
                return

            encrypted_key_b64 = encrypt_sym_key(
                self.session_key,
                self.server_rsa_public_key
            )

            packet = f"KEY_EXCHANGE|{encrypted_key_b64}"
            self.client_socket.send(packet.encode("utf-8"))

            self.key_sent = True
            self.log(f"[RSA] {algo} session key server'a gönderildi")

        self.log(f"[✔] {algo} anahtarı oluşturuldu")

    # ---------------- LISTEN SERVER ----------------
    def listen_server(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                parts = data.decode("utf-8").split("|")
                header = parts[0]

                # 🔐 RSA PUBLIC KEY
                if header == "RSA_PUBLIC_KEY":
                    self.server_rsa_public_key = base64.b64decode(parts[1])
                    self.log("[RSA] Sunucu public key alındı")
                    continue

                # 🔐 AES / DES cevabı
                if header in ["AES", "DES"]:
                    encrypted_msg = parts[1]
                    decrypted = decrypt_message(
                        header,
                        encrypted_msg,
                        self.session_key
                    )

                # 🔓 KLASİK cevaplar (opsiyonel)
                else:
                    encrypted_msg = parts[1]
                    decrypted = decrypt_message(
                        header,
                        encrypted_msg,
                        self.session_key
                    )

                self.log(f"\nSERVER ({header})")
                self.log(f"ÇÖZÜLMÜŞ: {decrypted}")

            except Exception as e:
                self.log(f"[HATA] Dinleme hatası: {e}")
                break

    # ---------------- SEND MESSAGE ----------------
    def send_message(self):
        if not self.client_socket:
            self.log("[HATA] Server'a bağlı değilsin")
            return

        if not self.session_key:
            self.log("[HATA] Önce anahtar oluşturmalısın!")
            return

        message = self.entry.get().strip()
        if not message:
            return

        algorithm = self.algorithm.get()

        try:
            encrypted = encrypt_message(
                algorithm,
                message,
                self.session_key
            )

            # 🔓 KLASİKLER
            if algorithm in ["Sezar", "Vigenere", "Affine", "Playfair", "Hill"]:
                packet = f"{algorithm}|{self.session_key}|{encrypted}"

            # 🔐 AES / DES
            else:
                if not self.key_sent:
                    self.log("[HATA] AES/DES anahtarı server'a gönderilmedi")
                    return
                packet = f"{algorithm}|{encrypted}"

            self.client_socket.send(packet.encode("utf-8"))

            self.log(f"\nSen ({algorithm})")
            self.log(f"ŞİFRELİ : {encrypted[:40]}...")
            self.log(f"ASIL    : {message}")

            self.entry.delete(0, tk.END)

        except Exception as e:
            self.log(f"[HATA] {e}")


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
