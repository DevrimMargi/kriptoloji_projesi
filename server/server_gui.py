import socket
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk

from sifreleme.crypto_manager import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 12345


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Server")
        self.root.geometry("650x540")
        self.root.resizable(False, False)

        self.conn = None

        # ---------------- STYLE ----------------
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 15, "bold"))

        # ---------------- HEADER ----------------
        header = ttk.Label(
            root,
            text="Python Secure Chat Server",
            style="Header.TLabel"
        )
        header.pack(pady=10)

        # ---------------- CHAT AREA ----------------
        self.text_area = ScrolledText(
            root,
            width=75,
            height=18,
            font=("Consolas", 10),
            bg="#f7f7f7"
        )
        self.text_area.pack(padx=10)
        self.text_area.config(state="disabled")

        # ---------------- CONTROL FRAME ----------------
        control = ttk.Frame(root)
        control.pack(pady=10, fill="x", padx=10)

        ttk.Label(control, text="Algoritma:").grid(row=0, column=0, padx=5)

        self.algorithm = tk.StringVar(value="Sezar")
        self.algo_box = ttk.Combobox(
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
                "AES (Manual)",
                "DES (Manual)"
            ],
            width=14,
            state="readonly"
        )
        self.algo_box.grid(row=0, column=1, padx=5)

        ttk.Label(control, text="Anahtar:").grid(row=0, column=2, padx=5)
        self.key_entry = ttk.Entry(control, width=14)
        self.key_entry.insert(0, "anahtar")
        self.key_entry.grid(row=0, column=3, padx=5)

        # ---------------- MESSAGE ENTRY ----------------
        self.entry = ttk.Entry(root, width=60)
        self.entry.pack(padx=10, pady=5)

        # ---------------- BUTTONS ----------------
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=8)

        ttk.Button(
            button_frame,
            text="📨 Gönder",
            command=self.send_message
        ).grid(row=0, column=0, padx=5)

        ttk.Button(
            button_frame,
            text="🚀 Server Başlat",
            command=self.start_server
        ).grid(row=0, column=1, padx=5)

    # ---------------- LOG ----------------
    def log(self, message):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state="disabled")
        self.text_area.yview(tk.END)

    # ---------------- SERVER START ----------------
    def start_server(self):
        threading.Thread(
            target=self.server_thread,
            daemon=True
        ).start()
        self.log("[SUNUCU] Server dinlemede: 127.0.0.1:12345")

    # ---------------- SERVER THREAD ----------------
    def server_thread(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)

        self.conn, addr = server_socket.accept()
        self.log(f"[BAĞLANTI] Client bağlandı: {addr}")

        while True:
            data = self.conn.recv(4096)
            if not data:
                self.log("[BAĞLANTI] Client ayrıldı")
                break

            try:
                data = data.decode("utf-8")
                algorithm, key, encrypted = data.split("|", 2)

                decrypted = decrypt_message(
                    algorithm,
                    encrypted,
                    key
                )

                self.log(f"\nKarşı Taraf ({algorithm})")
                self.log(f"ŞİFRELİ : {encrypted}")
                self.log(f"ÇÖZÜLMÜŞ: {decrypted}")

            except Exception as e:
                self.log(f"[HATA] {e}")

    # ---------------- SEND MESSAGE ----------------
    def send_message(self):
        if not self.conn:
            self.log("[HATA] Client bağlı değil")
            return

        message = self.entry.get()
        if not message.strip():
            return

        algorithm = self.algorithm.get()
        key = self.key_entry.get()

        try:
            encrypted = encrypt_message(
                algorithm,
                message,
                key
            )

            packet = f"{algorithm}|{key}|{encrypted}"
            self.conn.send(packet.encode("utf-8"))

            self.log(f"\nSen ({algorithm})")
            self.log(f"ŞİFRELİ : {encrypted}")
            self.log(f"ÇÖZÜLMÜŞ: {message}")

            self.entry.delete(0, tk.END)

        except Exception as e:
            self.log(f"[HATA] {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
