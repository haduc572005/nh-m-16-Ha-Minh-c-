import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import socket, threading, json, base64, os
from cryptography_utils import *
import datetime
from Crypto.PublicKey import RSA

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "Không xác định"

class SecureChatApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Chat - AES + RSA")
        self.window.state('zoomed')  # Mở toàn màn hình
        self.user_id = None

        self.setup_ui()
        self.load_keys()
        self.start_server()

    def setup_ui(self):
        left_frame = tk.Frame(self.window)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        connect_frame = tk.Frame(left_frame)
        connect_frame.pack(fill=tk.X, pady=5)

        tk.Label(connect_frame, text="Tên người dùng:").pack(side=tk.LEFT)
        self.entry_user = tk.Entry(connect_frame, width=12)
        self.entry_user.insert(0, "User_" + os.urandom(4).hex())
        self.entry_user.pack(side=tk.LEFT, padx=5)

        tk.Label(connect_frame, text="Port:").pack(side=tk.LEFT)
        self.entry_port = tk.Entry(connect_frame, width=8)
        self.entry_port.insert(0, "12345")
        self.entry_port.pack(side=tk.LEFT, padx=5)

        tk.Label(connect_frame, text="IP đích:").pack(side=tk.LEFT)
        self.entry_ip = tk.Entry(connect_frame, width=15)
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.pack(side=tk.LEFT, padx=5)

        self.btn_listen = tk.Button(connect_frame, text="Lắng nghe", command=self.start_server)
        self.btn_listen.pack(side=tk.LEFT, padx=5)

        self.btn_connect = tk.Button(connect_frame, text="Gửi (Bắt đầu)", command=self.send_message)
        self.btn_connect.pack(side=tk.LEFT, padx=5)

        self.btn_disconnect = tk.Button(connect_frame, text="Ngắt kết nối")
        self.btn_disconnect.pack(side=tk.LEFT, padx=5)

        tk.Button(connect_frame, text="Gửi File", command=self.send_file).pack(side=tk.LEFT, padx=5)

        self.label_local_ip = tk.Label(connect_frame, text=f"IP của bạn: {get_local_ip()}", fg="green")
        self.label_local_ip.pack(side=tk.LEFT, padx=5)

        tk.Label(left_frame, text="Thông tin Hệ thống", font=("Arial", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.system_log = scrolledtext.ScrolledText(left_frame, height=10, wrap=tk.WORD, bg="white", fg="black")
        self.system_log.pack(fill=tk.BOTH, expand=True)

        tk.Label(left_frame, text="Chat", font=("Arial", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.chat_log = scrolledtext.ScrolledText(left_frame, height=5, wrap=tk.WORD, bg="white", fg="blue")
        self.chat_log.pack(fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(left_frame, width=80)
        self.message_entry.pack(side=tk.LEFT, padx=5, pady=10)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.btn_send = tk.Button(left_frame, text="Gửi (Bắt đầu)", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=5)

        right_frame = tk.Frame(self.window)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=10)

        tk.Label(right_frame, text="Minh hoạ Quá trình Mã hoá / Giải mã", font=("Arial", 10, "bold")).pack()
        self.crypto_log = scrolledtext.ScrolledText(right_frame, width=80, height=35, wrap=tk.WORD, bg="#f9f9f9", fg="black")
        self.crypto_log.pack(fill=tk.BOTH, expand=True)

    def log_system(self, text):
        self.system_log.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.system_log.see(tk.END)

    def log_chat(self, text):
        self.chat_log.insert(tk.END, f"{text}\n")
        self.chat_log.see(tk.END)

    def log_crypto(self, text):
        self.crypto_log.insert(tk.END, f"{text}\n")
        self.crypto_log.see(tk.END)

    def load_keys(self):
        os.makedirs("keys", exist_ok=True)
        if not os.path.exists("keys/sender_private.pem"):
            self.generate_rsa_keys("keys/sender")
        if not os.path.exists("keys/receiver_private.pem"):
            self.generate_rsa_keys("keys/receiver")

        with open("keys/sender_private.pem", "rb") as f:
            self.sender_private = f.read()
        with open("keys/sender_public.pem", "rb") as f:
            self.sender_public = f.read()
        with open("keys/receiver_private.pem", "rb") as f:
            self.receiver_private = f.read()
        with open("keys/receiver_public.pem", "rb") as f:
            self.receiver_public = f.read()

    def generate_rsa_keys(self, prefix):
        key = RSA.generate(2048)
        with open(f"{prefix}_private.pem", "wb") as f:
            f.write(key.export_key())
        with open(f"{prefix}_public.pem", "wb") as f:
            f.write(key.publickey().export_key())

    def send_message(self):
        try:
            user = self.entry_user.get().strip()
            msg = self.message_entry.get().strip()
            if not msg:
                return
            key, iv = generate_aes_key_iv()
            cipher = aes_encrypt(key, iv, msg)
            enc_key = rsa_encrypt_key(self.receiver_public, key)
            digest = sha256_hash(iv + cipher)
            signature = sign_sha256(self.sender_private, user)
            packet = {
                "type": "message",
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(cipher).decode(),
                "enc_key": base64.b64encode(enc_key).decode(),
                "hash": digest,
                "signature": base64.b64encode(signature).decode(),
                "metadata": user
            }
            with socket.create_connection((self.entry_ip.get(), int(self.entry_port.get())), timeout=3) as s:
                s.send(json.dumps(packet).encode())
                ack = s.recv(1024).decode()
            self.log_system(f"Gửi thành công: {msg} (ACK={ack})")
            self.log_chat(f"Bạn: {msg}")
            self.log_crypto(f"[Mã hoá] IV: {iv.hex()}")
            self.log_crypto(f"[Mã hoá] Cipher: {cipher.hex()}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()
        user = self.entry_user.get().strip()
        key, iv = generate_aes_key_iv()
        cipher = aes_encrypt(key, iv, file_data)
        enc_key = rsa_encrypt_key(self.receiver_public, key)
        digest = sha256_hash(iv + cipher)
        signature = sign_sha256(self.sender_private, user)
        packet = {
            "type": "file",
            "filename": filename,
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(cipher).decode(),
            "enc_key": base64.b64encode(enc_key).decode(),
            "hash": digest,
            "signature": base64.b64encode(signature).decode(),
            "metadata": user
        }
        try:
            with socket.create_connection((self.entry_ip.get(), int(self.entry_port.get())), timeout=3) as s:
                s.send(json.dumps(packet).encode())
                ack = s.recv(1024).decode()
            self.log_system(f"Đã gửi file: {filename} (ACK={ack})")
        except Exception as e:
            self.log_system(f"Lỗi gửi file: {str(e)}")

    def start_server(self):
        def handle_client(conn, addr):
            try:
                data = json.loads(conn.recv(8192).decode())
                iv = base64.b64decode(data["iv"])
                cipher = base64.b64decode(data["cipher"])
                enc_key = base64.b64decode(data["enc_key"])
                signature = base64.b64decode(data["signature"])
                key = rsa_decrypt_key(self.receiver_private, enc_key)
                plain = aes_decrypt(key, iv, cipher)
                digest = sha256_hash(iv + cipher)
                if digest == data["hash"] and verify_sha256_signature(self.sender_public, data["metadata"], signature):
                    if data["type"] == "message":
                        self.log_system(f"Nhận từ {addr}: {plain}")
                        self.log_chat(f"Đối phương: {plain}")
                        self.log_crypto(f"[Giải mã] IV: {iv.hex()}")
                        conn.send(b"ACK")
                    elif data["type"] == "file":
                        filename = data["filename"]
                        os.makedirs("received_files", exist_ok=True)
                        save_path = os.path.join("received_files", f"received_{filename}")
                        with open(save_path, "wb") as f:
                            f.write(plain)
                        self.log_system(f"📥 File nhận: {filename}, lưu tại {save_path}")
                        self.log_crypto(f"[Giải mã File] OK - Đã lưu")
                        conn.send(b"ACK")
                else:
                    self.log_system("❌ Lỗi xác thực hoặc toàn vẹn dữ liệu")
                    conn.send(b"NACK")
            except Exception as e:
                self.log_system(f"[Lỗi Server] {str(e)}")
            finally:
                conn.close()

        def server_loop():
            s = socket.socket()
            s.bind(("0.0.0.0", int(self.entry_port.get())))
            s.listen(5)
            self.log_system("Đang lắng nghe...")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

        threading.Thread(target=server_loop, daemon=True).start()

    def run(self):
        self.window.mainloop()
