import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import socket
import threading
import base64
import os
import time
import random
import string

# ---- proje içi modüller ----
from sifreleme.crypto_manager import encrypt_message, decrypt_message
from sifreleme.asymmetric.rsa_key_exchange import encrypt_sym_key
from sifreleme.asymmetric.ecc_key_exchange import (
    generate_ecc_keys,
    serialize_public_key,
    load_public_key,
    derive_shared_key
)

HOST = "127.0.0.1"
PORT = 12345


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Client")
        self.root.geometry("650x560")
        self.root.resizable(False, False)

        self.client_socket = None
        self.session_key = None
        self.server_rsa_public_key = None
        self.server_ecc_public_key = None
        self.key_sent = False

        # ECC key pair (client)
        self.ecc_private_key, self.ecc_public_key = generate_ecc_keys()

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

        # -------- Algoritma --------
        ttk.Label(control, text="Algoritma:").grid(row=0, column=0, padx=5)

        self.algorithm = tk.StringVar()
        self.algorithm_combo = ttk.Combobox(
            control,
            textvariable=self.algorithm,
            state="readonly",
            width=15
        )
        self.algorithm_combo.grid(row=0, column=1, padx=5)

        # -------- Anahtar Paylaşım --------
        ttk.Label(control, text="Anahtar Paylaşım:").grid(row=1, column=0, padx=5)

        self.key_exchange = tk.StringVar(value="—")
        self.key_exchange_combo = ttk.Combobox(
            control,
            textvariable=self.key_exchange,
            values=["—", "RSA", "ECC"],
            state="readonly",
            width=15
        )
        self.key_exchange_combo.grid(row=1, column=1, padx=5)

        ttk.Button(
            control,
            text="🔐 Anahtar Oluştur",
            command=self.generate_key
        ).grid(row=0, column=2, rowspan=2, padx=10)

        self.entry = ttk.Entry(self.root, width=60)
        self.entry.pack(pady=5)

        btns = ttk.Frame(self.root)
        btns.pack(pady=5)

        ttk.Button(btns, text="📨 Gönder", command=self.send_message).grid(row=0, column=0, padx=5)
        ttk.Button(btns, text="🔌 Server'a Bağlan", command=self.connect).grid(row=0, column=1, padx=5)

        # başlangıç durumu
        self.set_classic_algorithms()
        self.key_exchange.trace_add("write", self.on_key_exchange_change)

    # ---------------- ALGORITHM SETTERS ----------------
    def set_classic_algorithms(self):
        self.algorithm_combo.config(values=[
            "Sezar",
            "Vigenere",
            "Affine",
            "Playfair",
            "Hill"
        ])
        self.algorithm.set("Sezar")

    def set_symmetric_algorithms(self):
        self.algorithm_combo.config(values=[
            "AES",
            "AES (Manual)",
            "DES",
            "DES (Manual)"
        ])
        self.algorithm.set("AES")

    def on_key_exchange_change(self, *args):
        if self.key_exchange.get() == "—":
            self.set_classic_algorithms()
        else:
            self.set_symmetric_algorithms()

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

            threading.Thread(target=self.listen_server, daemon=True).start()

        except Exception as e:
            self.log(f"[HATA] {e}")

    # ---------------- KEY GENERATION ----------------
    def generate_key(self):
        algo = self.algorithm.get()
        self.key_sent = False

        # 🔐 KLASİK ŞİFRELEMELER → OTOMATİK ANAHTAR
        if algo == "Sezar":
            self.session_key = random.randint(1, 25)

        elif algo == "Vigenere":
            self.session_key = ''.join(random.choices(string.ascii_uppercase, k=6))

        elif algo == "Affine":
            a = random.choice([3, 5, 7, 11, 17, 19, 23, 25])
            b = random.randint(0, 25)
            self.session_key = f"{a},{b}"

        elif algo == "Playfair":
            self.session_key = ''.join(random.sample("ABCDEFGHIKLMNOPQRSTUVWXYZ", 5))

        elif algo == "Hill":
            self.session_key = "2,3;1,4"

        if algo in ["Sezar", "Vigenere", "Affine", "Playfair", "Hill"]:
            self.key_sent = True
            self.log("[INFO] Klasik şifreleme – anahtar otomatik oluşturuldu")
            return

        # 🔐 SİMETRİK (AES / DES)
        key_method = self.key_exchange.get()
        key_length = 16 if "AES" in algo else 8

        # 🔵 RSA
        if key_method == "RSA":
            self.session_key = os.urandom(key_length)

            encrypted_key = encrypt_sym_key(
                self.session_key,
                self.server_rsa_public_key
            )

            self.client_socket.send(
                f"KEY_EXCHANGE|{algo}|{encrypted_key}".encode("utf-8")
            )

            self.key_sent = True
            self.log(f"[RSA] {algo} session key gönderildi")

        # 🟢 ECC
        elif key_method == "ECC":
            pub_bytes = serialize_public_key(self.ecc_public_key)
            pub_b64 = base64.b64encode(pub_bytes).decode()

            self.client_socket.send(
                f"ECC_PUBLIC_KEY|{pub_b64}".encode("utf-8")
            )
            self.log("[ECC] Client public key gönderildi")

            while self.server_ecc_public_key is None:
                time.sleep(0.1)

            self.session_key = derive_shared_key(
                self.ecc_private_key,
                self.server_ecc_public_key,
                key_length
            )

            self.key_sent = True
            self.log(f"[ECC] {algo} session key üretildi")

    # ---------------- LISTEN SERVER ----------------
    def listen_server(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                msg = data.decode()

                if msg.startswith("RSA_PUBLIC_KEY|"):
                    self.server_rsa_public_key = base64.b64decode(msg.split("|")[1])
                    self.log("[RSA] Server public key alındı")
                    continue

                if msg.startswith("ECC_PUBLIC_KEY|"):
                    pem = base64.b64decode(msg.split("|")[1])
                    self.server_ecc_public_key = load_public_key(pem)
                    self.log("[ECC] Server public key alındı")
                    continue

                algo, encrypted_msg = msg.split("|", 1)

                decrypted = decrypt_message(
                    algo,
                    encrypted_msg,
                    self.session_key
                )

                self.log(f"\nSERVER ({algo})")
                self.log(f"ÇÖZÜLMÜŞ: {decrypted}")

            except Exception as e:
                self.log(f"[HATA] {e}")
                break

    # ---------------- SEND MESSAGE ----------------
    def send_message(self):
        if not self.client_socket or not self.session_key:
            self.log("[HATA] Bağlantı veya anahtar yok")
            return

        message = self.entry.get().strip()
        if not message:
            return

        algo = self.algorithm.get()
        encrypted = encrypt_message(algo, message, self.session_key)

        if algo in ["Sezar", "Vigenere", "Affine", "Playfair", "Hill"]:
            packet = f"{algo}|{self.session_key}|{encrypted}"
        else:
            packet = f"{algo}|{encrypted}"

        self.client_socket.send(packet.encode())

        self.log(f"\nSen ({algo})")
        self.log(f"ŞİFRELİ : {encrypted[:40]}...")
        self.log(f"ASIL    : {message}")

        self.entry.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()
