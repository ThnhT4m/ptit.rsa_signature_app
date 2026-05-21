import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext

from crypto_utils import (
    generate_keys,
    sign_data,
    verify_signature,
    read_file_bytes,
    save_signature,
    read_signature
)


class RSASignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Digital Signature Application")
        self.root.geometry("850x650")
        self.root.resizable(False, False)

        os.makedirs("keys", exist_ok=True)
        os.makedirs("signatures", exist_ok=True)

        self.private_key_path = "keys/private_key.pem"
        self.public_key_path = "keys/public_key.pem"

        self.file_path = None
        self.signature_path = None

        self.build_ui()

    def build_ui(self):
        title = tk.Label(
            self.root,
            text="RSA Digital Signature Application",
            font=("Arial", 20, "bold")
        )
        title.pack(pady=10)

        # ===================== KEY FRAME =====================
        key_frame = tk.LabelFrame(
            self.root,
            text="1. Sinh cặp khóa RSA",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        key_frame.pack(fill="x", padx=20, pady=8)

        tk.Button(
            key_frame,
            text="Sinh khóa RSA",
            width=20,
            command=self.generate_key_pair
        ).grid(row=0, column=0, padx=5)

        self.key_status_label = tk.Label(
            key_frame,
            text="Chưa sinh khóa",
            fg="red"
        )
        self.key_status_label.grid(row=0, column=1, padx=10)

        # ===================== SIGN TEXT FRAME =====================
        text_frame = tk.LabelFrame(
            self.root,
            text="2. Ký văn bản",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        text_frame.pack(fill="both", padx=20, pady=8)

        self.text_input = scrolledtext.ScrolledText(
            text_frame,
            width=90,
            height=7
        )
        self.text_input.pack(pady=5)

        tk.Button(
            text_frame,
            text="Ký văn bản",
            width=20,
            command=self.sign_text
        ).pack(pady=5)

        # ===================== SIGN FILE FRAME =====================
        file_frame = tk.LabelFrame(
            self.root,
            text="3. Ký file",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        file_frame.pack(fill="x", padx=20, pady=8)

        tk.Button(
            file_frame,
            text="Chọn file",
            width=15,
            command=self.choose_file
        ).grid(row=0, column=0, padx=5)

        self.file_label = tk.Label(
            file_frame,
            text="Chưa chọn file",
            width=60,
            anchor="w"
        )
        self.file_label.grid(row=0, column=1, padx=5)

        tk.Button(
            file_frame,
            text="Ký file",
            width=15,
            command=self.sign_file
        ).grid(row=0, column=2, padx=5)

        # ===================== VERIFY FRAME =====================
        verify_frame = tk.LabelFrame(
            self.root,
            text="4. Xác minh chữ ký",
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        verify_frame.pack(fill="x", padx=20, pady=8)
        tk.Button(
            verify_frame,
            text="Xác minh văn bản",
            width=15,
            command=self.verify_text
        ).grid(row=0, column=3, padx=10, pady=5)
        tk.Button(
            verify_frame,
            text="Chọn file gốc",
            width=18,
            command=self.choose_file
        ).grid(row=0, column=0, padx=5, pady=5)

        tk.Button(
            verify_frame,
            text="Chọn chữ ký .sig",
            width=18,
            command=self.choose_signature
        ).grid(row=0, column=1, padx=5, pady=5)

        tk.Button(
            verify_frame,
            text="Xác minh",
            width=18,
            command=self.verify_file
        ).grid(row=0, column=2, padx=5, pady=5)

        self.signature_label = tk.Label(
            verify_frame,
            text="Chưa chọn chữ ký",
            anchor="w"
        )
        self.signature_label.grid(row=1, column=0, columnspan=3, sticky="w", padx=5)

        # ===================== RESULT FRAME =====================
        result_frame = tk.Frame(self.root)
        result_frame.pack(fill="x", padx=20, pady=15)

        self.result_label = tk.Label(
            result_frame,
            text="Kết quả: Đang chờ thao tác",
            font=("Arial", 15, "bold"),
            fg="blue"
        )
        self.result_label.pack()

    # ============================================================
    # SINH KHÓA
    # ============================================================
    def generate_key_pair(self):
        password = simpledialog.askstring(
            "Mật khẩu private key",
            "Nhập mật khẩu để bảo vệ private key:",
            show="*"
        )

        if not password:
            messagebox.showwarning("Cảnh báo", "Bạn chưa nhập mật khẩu.")
            return

        confirm_password = simpledialog.askstring(
            "Xác nhận mật khẩu",
            "Nhập lại mật khẩu:",
            show="*"
        )

        if password != confirm_password:
            messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp.")
            return

        try:
            generate_keys(
                private_key_path=self.private_key_path,
                public_key_path=self.public_key_path,
                password=password
            )

            self.key_status_label.config(
                text="Đã sinh khóa thành công",
                fg="green"
            )

            messagebox.showinfo(
                "Thành công",
                "Đã sinh cặp khóa RSA thành công!\n\n"
                # "Private key: keys/private_key.pem\n"
                # "Public key: keys/public_key.pem"
            )

        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể sinh khóa:\n{e}")

    # ============================================================
    # CHỌN FILE
    # ============================================================
    def choose_file(self):
        path = filedialog.askopenfilename(
            title="Chọn file",
            filetypes=[
                ("All files", "*.*"),
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("Word files", "*.docx")
            ]
        )

        if path:
            self.file_path = path
            self.file_label.config(text=path)

    # ============================================================
    # CHỌN CHỮ KÝ
    # ============================================================
    def choose_signature(self):
        path = filedialog.askopenfilename(
            title="Chọn file chữ ký",
            filetypes=[
                ("Signature files", "*.sig"),
                ("All files", "*.*")
            ]
        )

        if path:
            self.signature_path = path
            self.signature_label.config(text=f"Chữ ký: {path}")

    # ============================================================
    # KÝ VĂN BẢN
    # ============================================================
    def sign_text(self):
        text = self.text_input.get("1.0", tk.END).strip()

        if not text:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập văn bản cần ký.")
            return

        if not os.path.exists(self.private_key_path):
            messagebox.showwarning("Cảnh báo", "Chưa có private key. Hãy sinh khóa trước.")
            return

        password = simpledialog.askstring(
            "Mật khẩu private key",
            "Nhập mật khẩu private key:",
            show="*"
        )

        if not password:
            messagebox.showwarning("Cảnh báo", "Bạn chưa nhập mật khẩu.")
            return

        try:
            data = text.encode("utf-8")

            signature = sign_data(
                data=data,
                private_key_path=self.private_key_path,
                password=password
            )

            save_path = filedialog.asksaveasfilename(
                title="Lưu chữ ký văn bản",
                defaultextension=".sig",
                initialdir="signatures",
                initialfile="text_signature.sig",
                filetypes=[("Signature files", "*.sig")]
            )

            if save_path:
                save_signature(signature, save_path)

                self.result_label.config(
                    text="Kết quả: Ký văn bản thành công",
                    fg="green"
                )

                messagebox.showinfo(
                    "Thành công",
                    f"Đã ký văn bản thành công!\n\nFile chữ ký:\n{save_path}"
                )

        except Exception as e:
            self.result_label.config(
                text="Kết quả: Ký văn bản thất bại",
                fg="red"
            )
            messagebox.showerror(
                "Lỗi",
                f"Không thể ký văn bản.\nCó thể mật khẩu sai hoặc private key không hợp lệ.\n\n{e}"
            )

    # ============================================================
    # KÝ FILE
    # ============================================================
    def sign_file(self):
        if not self.file_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file cần ký.")
            return

        if not os.path.exists(self.private_key_path):
            messagebox.showwarning("Cảnh báo", "Chưa có private key. Hãy sinh khóa trước.")
            return

        password = simpledialog.askstring(
            "Mật khẩu private key",
            "Nhập mật khẩu private key:",
            show="*"
        )

        if not password:
            messagebox.showwarning("Cảnh báo", "Bạn chưa nhập mật khẩu.")
            return

        try:
            data = read_file_bytes(self.file_path)

            signature = sign_data(
                data=data,
                private_key_path=self.private_key_path,
                password=password
            )

            file_name = os.path.basename(self.file_path)
            default_signature_name = file_name + ".sig"

            save_path = filedialog.asksaveasfilename(
                title="Lưu chữ ký file",
                defaultextension=".sig",
                initialdir="signatures",
                initialfile=default_signature_name,
                filetypes=[("Signature files", "*.sig")]
            )

            if save_path:
                save_signature(signature, save_path)

                self.result_label.config(
                    text="Kết quả: Ký file thành công",
                    fg="green"
                )

                messagebox.showinfo(
                    "Thành công",
                    f"Đã ký file thành công!\n\nFile chữ ký:\n{save_path}"
                )

        except Exception as e:
            self.result_label.config(
                text="Kết quả: Ký file thất bại",
                fg="red"
            )
            messagebox.showerror(
                "Lỗi",
                f"Không thể ký file.\nCó thể mật khẩu sai hoặc private key không hợp lệ.\n\n{e}"
            )

    # ============================================================
    # XÁC MINH FILE
    # ============================================================
    def verify_file(self):
        if not self.file_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file gốc.")
            return

        if not self.signature_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file chữ ký .sig.")
            return

        if not os.path.exists(self.public_key_path):
            messagebox.showwarning("Cảnh báo", "Chưa có public key. Hãy sinh khóa trước.")
            return

        try:
            data = read_file_bytes(self.file_path)
            signature = read_signature(self.signature_path)

            is_valid = verify_signature(
                data=data,
                signature=signature,
                public_key_path=self.public_key_path
            )

            if is_valid:
                self.result_label.config(
                    text="Kết quả: Chữ ký HỢP LỆ",
                    fg="green"
                )

                messagebox.showinfo(
                    "Xác minh thành công",
                    "Chữ ký hợp lệ.\n\nFile chưa bị thay đổi và đúng public key."
                )
            else:
                self.result_label.config(
                    text="Kết quả: Chữ ký KHÔNG HỢP LỆ",
                    fg="red"
                )

                messagebox.showerror(
                    "Xác minh thất bại",
                    "Chữ ký không hợp lệ.\n\nCó thể file đã bị sửa, chữ ký sai hoặc dùng sai public key."
                )

        except Exception as e:
            self.result_label.config(
                text="Kết quả: Lỗi xác minh",
                fg="red"
            )

            messagebox.showerror(
                "Lỗi",
                f"Không thể xác minh chữ ký:\n{e}"
            )
    def verify_text(self):
        text = self.text_input.get("1.0", tk.END).strip()

        if not text:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập văn bản gốc cần xác minh.")
            return

        if not self.signature_path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file chữ ký .sig.")
            return

        if not os.path.exists(self.public_key_path):
            messagebox.showwarning("Cảnh báo", "Chưa có public key. Hãy sinh khóa trước.")
            return

        try:
            data = text.encode("utf-8")
            signature = read_signature(self.signature_path)

            is_valid = verify_signature(
                data=data,
                signature=signature,
                public_key_path=self.public_key_path
            )

            if is_valid:
                self.result_label.config(
                    text="Kết quả: Văn bản HỢP LỆ",
                    foreground="#15803d"
                )
                messagebox.showinfo(
                    "Xác minh thành công",
                    "Chữ ký hợp lệ.\n\nVăn bản chưa bị thay đổi."
                )
            else:
                self.result_label.config(
                    text="Kết quả: Văn bản KHÔNG HỢP LỆ",
                foreground="#dc2626"
            )
            messagebox.showerror(
                "Xác minh thất bại",
                "Chữ ký không hợp lệ.\n\nCó thể văn bản đã bị sửa hoặc dùng sai chữ ký."
            )

        except Exception as e:
            self.result_label.config(
                text="Kết quả: Lỗi xác minh văn bản",
                foreground="#dc2626"
            )
            messagebox.showerror("Lỗi", f"Không thể xác minh văn bản:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSASignatureApp(root)
    root.mainloop()