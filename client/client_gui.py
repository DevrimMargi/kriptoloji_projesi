import socket
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk

from sifreleme.crypto_manager import encrypt_message, decrypt_message

HOST = "127.0.0.1"
PORT = 12345


class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Chat Client")
        self.root.geometry("600x520")
        self.root.resizable(False, False)

        # --- STYLE ---
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TButton", padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))

        # --- HEADER ---
        header = ttk.Label(root, text="Python Secure Chat Client", style="Header.TLabel")
        header.pack(pady=10)

        # --- CHAT AREA ---
        self.text_area = ScrolledText(
            root,
            width=70,
            height=18,
            font=("Consolas", 10),
            bg="#f7f7f7"
        )
        self.text_area.pack(padx=10)
        self.text_area.config(state="disabled")

        # --- CONTROL FRAME ---
        control = ttk.Frame(root)
        control.pack(pady=10, fill="x", padx=10)

        ttk.Label(control, text="Algoritma:").grid(row=0, column=0, padx=5)
        self.algorithm = tk.StringVar(value="Sezar")
        self.algorithm_box = ttk.Combobox(
            control,
            textvariable=self.algorithm,
            values=["Sezar", "Vigenere", "Affine", "Playfair", "Hill"],
            width=12,
            state="readonly"
        )
        self.algorithm_box.grid(row=0, column=1, padx=5)

        ttk.Label(control, text="Anahtar:").grid(row=0, column=2, padx=5)
        self.key_entry = ttk.Entry(control, width=10)
        self.key_entry.insert(0, "3")
        self.key_entry.grid(row=0, column=3, padx=5)

        # --- MESSAGE ENTRY ---
        self.entry = ttk.Entry(root, width=55)
        self.entry.pack(padx=10, pady=5)

        # --- BUTTONS ---
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="📨 Gönder", command=self.send_message).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="🔌 Server'a Bağlan", command=self.connect).grid(row=0, column=1, padx=5)

        self.client_socket = None

    def log(self, message):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state="disabled")
        self.text_area.yview(tk.END)

    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.log("Sen: Server'a bağlandın.")

            threading.Thread(target=self.listen_server, daemon=True).start()
        except Exception as e:
            self.log(f"[HATA] {e}")

    def listen_server(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.log("Karşı taraf bağlantıyı kapattı.")
                    break

                data = data.decode("utf-8")
                algorithm, key, encrypted = data.split("|")

                decrypted = decrypt_message(algorithm, encrypted, key)

                self.log(f"\nKarşı taraf ({algorithm}):")
                self.log(f"ŞİFRELİ : {encrypted}")
                self.log(f"ÇÖZÜLMÜŞ: {decrypted}")

            except:
                break

    def send_message(self):
        if not self.client_socket:
            self.log("[HATA] Server'a bağlı değilsin")
            return

        message = self.entry.get()
        if not message.strip():
            return

        algorithm = self.algorithm.get()
        key = self.key_entry.get()

        try:
            encrypted = encrypt_message(algorithm, message, key)
            packet = f"{algorithm}|{key}|{encrypted}"
            self.client_socket.send(packet.encode("utf-8"))

            self.log(f"\nSen ({algorithm}):")
            self.log(f"ŞİFRELİ : {encrypted}")
            self.log(f"ÇÖZÜLMÜŞ: {message}")

            self.entry.delete(0, tk.END)

        except Exception as e:
            self.log(f"[HATA] {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
