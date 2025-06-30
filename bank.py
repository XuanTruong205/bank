import hashlib
import json
import random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import ttk

names = [
    "Nguyễn Văn An", "Nguyễn Thị Hạnh", "Trần Văn Bình", "Trần Thị Thu",
    "Lê Văn Cường", "Lê Thị Mai", "Phạm Văn Dũng", "Phạm Thị Lan",
    "Hoàng Văn Minh", "Hoàng Thị Ngọc", "Đỗ Văn Nam", "Đỗ Thị Hoa",
    "Bùi Văn Quang", "Bùi Thị Hương", "Vũ Văn Sơn", "Vũ Thị Yến",
    "Đặng Văn Thái", "Đặng Thị Hằng", "Ngô Văn Huy", "Ngô Thị Kim"
]

def generate_transaction(valid=True, level=1):
    nguoi_gui = random.choice(names)
    nguoi_nhan = random.choice([n for n in names if n != nguoi_gui])
    so_tien = round(random.uniform(100_000, 5_000_000), -3) if level == 1 else (
             round(random.uniform(5_000_000, 100_000_000), -3) if level == 2 else
             round(random.uniform(100_000_000, 500_000_000), -3))

    tx = {
        'nguoi_gui': nguoi_gui,
        'nguoi_nhan': nguoi_nhan,
        'tai_khoan_gui': str(random.randint(1000000000, 9999999999)),
        'tai_khoan_nhan': str(random.randint(1000000000, 9999999999)),
        'so_tien': so_tien
    }

    if not valid:
        error_type = random.choice([
            "missing_tai_khoan_nhan", "missing_nguoi_gui", "negative_so_tien",
            "same_accounts", "missing_so_tien", "invalid_account_format",
            "missing_nguoi_nhan", "excessive_so_tien", "malicious_name",
            "malicious_account", "strange_field"
        ])
        if error_type == "missing_tai_khoan_nhan": del tx['tai_khoan_nhan']
        elif error_type == "missing_nguoi_gui": del tx['nguoi_gui']
        elif error_type == "negative_so_tien": tx['so_tien'] = -random.uniform(100_000, 500_000_000)
        elif error_type == "same_accounts": tx['tai_khoan_nhan'] = tx['tai_khoan_gui']
        elif error_type == "missing_so_tien": del tx['so_tien']
        elif error_type == "invalid_account_format": tx['tai_khoan_nhan'] = str(random.randint(1000, 99999))
        elif error_type == "missing_nguoi_nhan": del tx['nguoi_nhan']
        elif error_type == "excessive_so_tien": tx['so_tien'] = random.uniform(1_000_000_000, 5_000_000_000)
        elif error_type == "malicious_name": tx['nguoi_gui'] = "<script>alert('XSS')</script>"
        elif error_type == "malicious_account": tx['tai_khoan_nhan'] = "' OR '1'='1"
        elif error_type == "strange_field": tx['truong_la'] = "Trường dữ liệu bất thường"

    return tx

class EncryptionGameApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hệ thống mã hóa ngân hàng")
        self.geometry("950x800")
        self.configure(bg='#f0f4f7')

        self.level = tk.StringVar(value="1 - Dễ")
        self.feedback_text = tk.StringVar()
        self.score = 0
        self.score_text = tk.StringVar(value="Điểm: 0")

        self.transactions = []
        self.current_tx = None
        self.encrypted = None
        self.signature = None
        self.status = {'encrypted': False, 'signed': False, 'checked': False}

        self.setup_ui()
        self.update_transactions()

        self.history = []

    def setup_ui(self):
        tk.Label(self, text="🔐 Hệ thống mã hóa ngân hàng", font=("Helvetica", 18, "bold"), bg='#f0f4f7').pack(pady=15)

        top_frame = tk.Frame(self, bg='#f0f4f7')
        top_frame.pack(pady=10)

        ttk.Label(top_frame, text="Chọn cấp độ:").grid(row=0, column=0, padx=5)
        level_menu = ttk.Combobox(top_frame, textvariable=self.level, values=["1 - Dễ", "2 - Trung bình", "3 - Khó"], state='readonly', width=15)
        level_menu.grid(row=0, column=1, padx=5)
        level_menu.current(0)
        level_menu.bind("<<ComboboxSelected>>", lambda e: self.update_transactions())

        ttk.Label(top_frame, text="Chọn giao dịch:").grid(row=0, column=2, padx=5)
        self.transaction_menu = ttk.Combobox(top_frame, state='readonly', width=60)
        self.transaction_menu.grid(row=0, column=3, padx=5)
        self.transaction_menu.bind("<<ComboboxSelected>>", lambda e: self.select_transaction())

        tk.Label(self, textvariable=self.score_text, font=("Helvetica", 13, "bold"), fg='green', bg='#f0f4f7').pack(pady=5)

        frame_info = tk.LabelFrame(self, text="📑 Thông tin giao dịch", bg='white', padx=10, pady=10)
        frame_info.pack(padx=20, pady=10, fill='x')
        self.info_text = tk.Label(frame_info, text="Chưa có giao dịch", font=("Helvetica", 13), bg='white', anchor='w', justify='left')
        self.info_text.pack(fill='x', padx=5, pady=5)

        frame_buttons = tk.Frame(self, bg='#f0f4f7')
        frame_buttons.pack(pady=10)
        tk.Button(frame_buttons, text="🔐 Mã hóa giao dịch", bg='#2196F3', fg='white', command=self.encrypt_transaction).grid(row=0, column=0, padx=5)
        tk.Button(frame_buttons, text="🖊 Xác thực giao dịch", bg='#FF9800', fg='white', command=self.sign_transaction).grid(row=0, column=1, padx=5)
        tk.Button(frame_buttons, text="🔍 Kiểm tra tính toàn vẹn", bg='#9C27B0', fg='white', command=self.check_transaction).grid(row=0, column=2, padx=5)
        tk.Button(frame_buttons, text="📜 Xem lịch sử giao dịch", bg='#607D8B', fg='white', command=self.show_history).grid(row=0, column=3, padx=5)

        frame_result = tk.LabelFrame(self, text="📋 Kết quả xử lý", bg='white', padx=10, pady=10)
        frame_result.pack(padx=20, pady=10, fill='both', expand=True)
        self.output = tk.Text(frame_result, height=15, font=("Consolas", 11), bg='#eef5f9', wrap='word')
        self.output.pack(fill='both', expand=True)

        self.output.tag_config('blue', foreground='#0066CC')    # Xanh dương đậm
        self.output.tag_config('orange', foreground="#FF6600")  # Cam đậm dễ nhìn
        self.output.tag_config('red', foreground='#CC0000')     # Đỏ đậm
        self.output.tag_config('green', foreground='#008000')   # Xanh lá đậm
        self.output.tag_config('yellow', foreground='#999900')  # Vàng đậm

        self.feedback_label = tk.Label(self, textvariable=self.feedback_text, font=("Helvetica", 13), bg='#f0f4f7', fg='blue', justify='left')
        self.feedback_label.pack(pady=10)

    def set_feedback(self, message, color="blue"):
        self.feedback_label.config(fg=color)
        self.feedback_text.set(message)

    def print_output(self, message, color=None):
        start_idx = self.output.index(tk.END)
        self.output.insert(tk.END, message + "\n")
        
        # Toàn bộ mặc định chữ đen
        self.output.tag_add('black', start_idx, self.output.index(tk.END))

        # Nếu có yêu cầu màu nhấn mạnh, chỉ bôi màu cho dòng vừa chèn
        if color:
            self.output.tag_add(color, start_idx, self.output.index(tk.END))

        self.output.see(tk.END)
        self.output.tag_config('black', foreground='black')

    def get_level_number(self):
        return int(self.level.get().split(" ")[0])

    def update_transactions(self):
        self.rsa_key = RSA.generate(1024 if self.get_level_number() == 1 else 2048 if self.get_level_number() == 2 else 3072)
        self.pub_key = self.rsa_key.publickey()
        self.aes_key = get_random_bytes(16)
        self.iv = get_random_bytes(16) if self.get_level_number() == 3 else b'abcdefghijklmnop'

        self.transactions.clear()
        lv = self.get_level_number()
        num_total = 3 if lv == 1 else 5 if lv == 2 else 7
        error_count = 1 if lv == 1 else 2 if lv == 2 else 3

        for _ in range(num_total - error_count):
            self.transactions.append(generate_transaction(valid=True, level=lv))
        for _ in range(error_count):
            self.transactions.append(generate_transaction(valid=False, level=lv))

        random.shuffle(self.transactions)
        options = []
        for i, tx in enumerate(self.transactions):
            nguoi_gui = tx.get('nguoi_gui', 'Không rõ')
            nguoi_nhan = tx.get('nguoi_nhan', 'Không rõ')
            so_tien = tx.get('so_tien', '-')
            so_tien_text = f"{so_tien:,.0f}₫" if isinstance(so_tien, (int, float)) else "Không hợp lệ"
            label = f"Giao dịch {i+1}: {nguoi_gui} → {nguoi_nhan} ({so_tien_text})"
            options.append(label)

        self.transaction_menu.config(values=options)

        self.transaction_menu.current(0)
        self.select_transaction()

    def select_transaction(self):
        idx = self.transaction_menu.current()
        self.current_tx = self.transactions[idx]
        self.encrypted = None
        self.signature = None
        self.status = {'encrypted': False, 'signed': False, 'checked': False}

        so_tien = self.current_tx.get('so_tien', '-')
        so_tien_text = f"{so_tien:,.0f}₫" if isinstance(so_tien, (int, float)) else "Không hợp lệ"
        info = (
            f"👤 Người gửi: {self.current_tx.get('nguoi_gui', '-')}\n\n"
            f"👤 Người nhận: {self.current_tx.get('nguoi_nhan', '-')}\n\n"
            f"🏦 Tài khoản gửi: {self.current_tx.get('tai_khoan_gui', '-')}\n\n"
            f"🏦 Tài khoản nhận: {self.current_tx.get('tai_khoan_nhan', '-')}\n\n"
            f"💰 Số tiền: {so_tien_text}"
        )

        self.info_text.config(text=info)
        self.output.delete(1.0, tk.END)

    def encrypt_transaction(self):
        if self.status['encrypted']:
            self.set_feedback("⚠ Giao dịch đã được mã hóa bằng AES.", color='orange')
            return

        json_data = json.dumps(self.current_tx, ensure_ascii=False).encode()
        padded = pad(json_data, AES.block_size)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv)
        self.encrypted = b64encode(cipher.encrypt(padded)).decode()
        self.status['encrypted'] = True

        self.print_output(f"[AES] Dữ liệu đã mã hóa:\n{self.encrypted}\n", 'blue')
        self.print_output(f"[Khóa AES] {self.aes_key.hex()[:16]}...", 'yellow')
        self.set_feedback("✅ Giao dịch đã được mã hóa thành công bằng AES.", color='green')

    def sign_transaction(self):
        if not self.status['encrypted']:
            self.set_feedback("⚠ Vui lòng mã hóa giao dịch bằng AES trước khi xác thực.", color='orange')
            return
        if self.status['signed']:
            self.set_feedback("⚠ Giao dịch đã được xác thực RSA.", color='orange')
            return

        h = SHA256.new(self.encrypted.encode())
        self.signature = pkcs1_15.new(self.rsa_key).sign(h)
        self.status['signed'] = True

        pubkey_short = self.pub_key.export_key().decode()[:60].replace('\n', '')
        sig_short = self.signature.hex()[:16] + "..."

        self.print_output("[RSA] Giao dịch đã được xác thực RSA.", 'orange')
        self.print_output(f"[Khóa RSA công khai] {pubkey_short}...", 'yellow')
        self.print_output(f"[Chữ ký số] {sig_short}\n", 'yellow')

        self.set_feedback("✅ Xác thực RSA thành công.", color='green')
        self.hacker_modify_data()

    def hacker_modify_data(self):
        lv = self.get_level_number()
        if lv < 2 or random.random() > 0.3:
            return  # Tỷ lệ 30% bị hacker can thiệp cấp 2 trở lên

        try:
            decrypted = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv).decrypt(b64decode(self.encrypted))
            data = json.loads(unpad(decrypted, AES.block_size).decode())

            attack = random.choice(["xss_name", "sql_injection", "so_tien_change"])
            if attack == "xss_name":
                data['nguoi_gui'] = "<script>alert('Hack')</script>"
                self.print_output("💀 Hacker đã chèn mã độc vào TÊN NGƯỜI GỬI!", 'red')
            elif attack == "sql_injection":
                data['tai_khoan_nhan'] = "' OR '1'='1"
                self.print_output("💀 Hacker đã tấn công SQL Injection vào TÀI KHOẢN NGƯỜI NHẬN!", 'red')
            elif attack == "so_tien_change":
                data['so_tien'] = random.uniform(1_000_000_000, 5_000_000_000)
                self.print_output("💀 Hacker đã thay đổi SỐ TIỀN giao dịch!", 'red')

            json_data = json.dumps(data, ensure_ascii=False).encode()
            padded = pad(json_data, AES.block_size)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv)
            self.encrypted = b64encode(cipher.encrypt(padded)).decode()
        except:
            self.output.insert(tk.END, "⚠ Hacker tấn công thất bại.\n")

    def check_transaction(self):
        if not self.status['signed']:
            self.set_feedback("⚠ Vui lòng xác thực RSA trước khi kiểm tra tính toàn vẹn.", color='orange')
            return
        if self.status['checked']:
            self.set_feedback("⚠ Đã thực hiện kiểm tra tính toàn vẹn SHA.", color='orange')
            return

        data = self.decrypt_transaction()
        if data is None:
            self.set_feedback("❌ Giao dịch không hợp lệ hoặc bị giả mạo.", color='red')
            self.increase_score(1)
            self.status['checked'] = True
            return

        valid_signature = self.verify_signature()
        errors = self.validate_transaction_fields(data)

        self.display_transaction_result(data, valid_signature, errors)
        self.status['checked'] = True
        
    def decrypt_transaction(self):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.iv)
        try:
            decrypted = cipher.decrypt(b64decode(self.encrypted))
            data = json.loads(unpad(decrypted, AES.block_size).decode())
            return data
        except json.JSONDecodeError:
            self.print_output("❌ Dữ liệu JSON không hợp lệ hoặc bị phá hỏng!", 'red')
            self.set_feedback("❌ Giải mã JSON thất bại, dữ liệu bị chỉnh sửa.", color='red')
        except (ValueError, KeyError) as e:
            self.print_output(f"❌ Lỗi giải mã AES: {str(e)}", 'red')
            self.set_feedback("❌ Giải mã AES thất bại, dữ liệu sai hoặc bị chỉnh sửa.", color='red')
        return None
        
    def verify_signature(self):
        h = SHA256.new(self.encrypted.encode())
        try:
            pkcs1_15.new(self.pub_key).verify(h, self.signature)
            return True
        except (ValueError, TypeError):
            return False
        
    def validate_transaction_fields(self, data):
        errors = []

        required_fields = ['nguoi_gui', 'nguoi_nhan', 'tai_khoan_gui', 'tai_khoan_nhan', 'so_tien']
        for field in required_fields:
            if field not in data:
                if field == 'so_tien':
                    errors.append("⚠️ Giao dịch thiếu thông tin số tiền.")
                else:
                    errors.append(f"⚠️ Giao dịch thiếu thông tin '{field}'.")

        if 'so_tien' in data:
            if not isinstance(data['so_tien'], (int, float)) or data['so_tien'] <= 0:
                errors.append("⚠️ Số tiền giao dịch không hợp lệ.")
            elif data['so_tien'] > 1_000_000_000:
                errors.append("⚠️ Số tiền vượt quá giới hạn cho phép.")

        if data.get('tai_khoan_nhan') == data.get('tai_khoan_gui'):
            errors.append("⚠️ Tài khoản gửi và nhận trùng nhau.")

        dangerous_fields = ['<script', 'alert', 'onerror', "'", '"', '--', ';']
        for field in ['nguoi_gui', 'nguoi_nhan', 'tai_khoan_gui', 'tai_khoan_nhan']:
            value = data.get(field, '').lower()
            if any(dangerous in value for dangerous in dangerous_fields):
                errors.append("🚨 Phát hiện dữ liệu nguy hiểm (có thể bị tấn công XSS hoặc SQL Injection).")

        original_json = json.dumps(self.current_tx, separators=(',', ':'), ensure_ascii=False)
        decrypted_json = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        if original_json != decrypted_json:
            errors.append("🚨 Dữ liệu giao dịch đã bị chỉnh sửa hoặc không khớp với bản gốc.")

        return errors

    def display_transaction_result(self, data, valid_signature, errors):
        so_tien = data.get('so_tien', '-')
        so_tien_text = f"{so_tien:,.0f}₫" if isinstance(so_tien, (int, float)) else "Không hợp lệ"

        self.print_output("[Giải mã AES] Dữ liệu sau giải mã:", 'blue')
        self.print_output(f"👤 Người gửi: {data.get('nguoi_gui', '-')}")
        self.print_output(f"👤 Người nhận: {data.get('nguoi_nhan', '-')}")
        self.print_output(f"🏦 Tài khoản gửi: {data.get('tai_khoan_gui', '-')}")
        self.print_output(f"🏦 Tài khoản nhận: {data.get('tai_khoan_nhan', '-')}")
        self.print_output(f"💰 Số tiền: {so_tien_text}")

        if 'truong_la' in data:
            self.print_output(f"⚠ Trường dữ liệu bất thường: {data['truong_la']}", 'red')

        if valid_signature and not errors:
            self.print_output("\n✅ Tính toàn vẹn giao dịch được đảm bảo bằng SHA.", 'green')
            self.set_feedback("✅ Giao dịch hợp lệ, dữ liệu an toàn.", color='green')
            self.increase_score(2)
        else:
            if not valid_signature:
                self.print_output("❌ Chữ ký số RSA không hợp lệ!", 'red')
            if errors:
                self.print_output("⚠ Phát hiện lỗi:\n" + "\n".join(f"- {e}" for e in errors), 'red')
            self.set_feedback("❌ Giao dịch không hợp lệ hoặc bị giả mạo.", color='red')
            self.increase_score(1)

        sha256_hash = hashlib.sha256(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        self.print_output(f"[SHA256] Giá trị băm của dữ liệu: {sha256_hash}", 'blue')
        # Cuối hàm display_transaction_result
        result_summary = {
            'nguoi_gui': data.get('nguoi_gui', '-'),
            'nguoi_nhan': data.get('nguoi_nhan', '-'),
            'so_tien': so_tien_text,
            'valid_signature': valid_signature,
            'errors': errors
        }
        self.history.append(result_summary)

    def show_history(self):
        history_window = tk.Toplevel(self)
        history_window.title("📜 Lịch sử giao dịch")
        history_window.geometry("700x500")
        history_window.configure(bg='white')

        frame = tk.Frame(history_window, bg='white')
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side='right', fill='y')

        history_text = tk.Text(frame, font=("Helvetica", 12), yscrollcommand=scrollbar.set, wrap='word', state='normal')
        history_text.pack(fill='both', expand=True)
        scrollbar.config(command=history_text.yview)

        if not self.history:
            history_text.insert(tk.END, "📌 Chưa có giao dịch nào được thực hiện.")
        else:
            for idx, entry in enumerate(self.history, 1):
                status_emoji = "✅" if entry['valid_signature'] and not entry['errors'] else "❌"
                error_summary = "\n      • ".join(entry['errors']) if entry['errors'] else "Không có lỗi."

                transaction_summary = (
                    f"📄 Giao dịch {idx}:\n\n"
                    f"   👤 Người gửi: {entry['nguoi_gui']}\n\n"
                    f"   👥 Người nhận: {entry['nguoi_nhan']}\n\n"
                    f"   💰 Số tiền: {entry['so_tien']}\n\n"
                    f"   📌 Trạng thái: {status_emoji} {'Hợp lệ' if status_emoji == '✅' else 'Không hợp lệ'}\n\n"
                    f"   ⚠️ Lỗi: {error_summary}\n\n"
                    f"{'─'*70}\n\n"
                )
                history_text.insert(tk.END, transaction_summary)

        history_text.config(state='disabled')  # Không cho phép chỉnh sửa

    def increase_score(self, points):
        self.score += points
        self.score_text.set(f"Điểm: {self.score}")

# Khởi chạy ứng dụng
if __name__ == "__main__":
    app = EncryptionGameApp()
    app.mainloop()
