import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext, ttk

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
        self.root.geometry("980x720")
        self.root.minsize(920, 680)
        self.root.configure(bg="#020617")


        self.font_family = "DejaVu Sans"
        self.mono_font_family = "DejaVu Sans Mono"
        self.root.option_add("*Font", "{DejaVu Sans} 10")

        os.makedirs("keys", exist_ok=True)
        os.makedirs("signatures", exist_ok=True)

        self.private_key_path = "keys/private_key.pem"
        self.public_key_path = "keys/public_key.pem"

        self.file_path = None
        self.signature_path = None

        self.setup_style()
        self.build_ui()

    # ============================================================
    # STYLE
    # ============================================================
    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure(
            "Root.TFrame",
            background="#020617"
        )

        self.style.configure(
            "Sidebar.TFrame",
            background="#0b1220"
        )

        self.style.configure(
            "Card.TLabelframe",
            background="#0f172a",
            borderwidth=1,
            relief="solid"
        )

        self.style.configure(
            "Card.TLabelframe.Label",
            background="#0f172a",
            foreground="#e5e7eb",
            font=("DejaVu Sans", 11, "bold")
        )

        self.style.configure(
            "TLabel",
            background="#0f172a",
            foreground="#e5e7eb",
            font=("DejaVu Sans", 10)
        )

        self.style.configure(
            "Muted.TLabel",
            background="#0f172a",
            foreground="#94a3b8",
            font=("DejaVu Sans", 9)
        )

        self.style.configure(
            "SidebarTitle.TLabel",
            background="#0b1220",
            foreground="#ffffff",
            font=("DejaVu Sans", 18, "bold")
        )

        self.style.configure(
            "SidebarText.TLabel",
            background="#0b1220",
            foreground="#d1d5db",
            font=("DejaVu Sans", 10)
        )

        self.style.configure(
            "Status.TLabel",
            background="#0f172a",
            foreground="#60a5fa",
            font=("DejaVu Sans", 14, "bold")
        )

        self.style.configure(
            "Primary.TButton",
            font=("DejaVu Sans", 10, "bold"),
            foreground="#ffffff",
            background="#2563eb",
            borderwidth=0,
            padding=(14, 9)
        )
        self.style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8"), ("pressed", "#1e40af")]
        )

        self.style.configure(
            "Success.TButton",
            font=("DejaVu Sans", 10, "bold"),
            foreground="#ffffff",
            background="#16a34a",
            borderwidth=0,
            padding=(14, 9)
        )
        self.style.map(
            "Success.TButton",
            background=[("active", "#15803d"), ("pressed", "#166534")]
        )

        self.style.configure(
            "Danger.TButton",
            font=("DejaVu Sans", 10, "bold"),
            foreground="#ffffff",
            background="#dc2626",
            borderwidth=0,
            padding=(14, 9)
        )
        self.style.map(
            "Danger.TButton",
            background=[("active", "#b91c1c"), ("pressed", "#991b1b")]
        )

        self.style.configure(
            "Ghost.TButton",
            font=("DejaVu Sans", 10),
            foreground="#e5e7eb",
            background="#334155",
            borderwidth=0,
            padding=(12, 8)
        )
        self.style.map(
            "Ghost.TButton",
            background=[("active", "#475569"), ("pressed", "#1e293b")]
        )

    # ============================================================
    # UI
    # ============================================================
    def build_ui(self):
        main = ttk.Frame(self.root, style="Root.TFrame")
        main.pack(fill="both", expand=True)

        sidebar = ttk.Frame(main, style="Sidebar.TFrame", width=250)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ttk.Label(
            sidebar,
            text="RSA\nSignature",
            style="SidebarTitle.TLabel",
            justify="left"
        ).pack(anchor="w", padx=24, pady=(35, 10))

        ttk.Label(
            sidebar,
            text="Ứng dụng ký số và xác minh chữ ký RSA cho văn bản hoặc file.",
            style="SidebarText.TLabel",
            wraplength=195,
            justify="left"
        ).pack(anchor="w", padx=24, pady=(0, 24))

        self.key_status_sidebar = ttk.Label(
            sidebar,
            text="● Chưa có khóa RSA",
            style="SidebarText.TLabel"
        )
        self.key_status_sidebar.pack(anchor="w", padx=24, pady=(0, 8))

        self.file_status_sidebar = ttk.Label(
            sidebar,
            text="● Chưa chọn file",
            style="SidebarText.TLabel",
            wraplength=190
        )
        self.file_status_sidebar.pack(anchor="w", padx=24, pady=(0, 8))

        self.sig_status_sidebar = ttk.Label(
            sidebar,
            text="● Chưa chọn chữ ký",
            style="SidebarText.TLabel",
            wraplength=190
        )
        self.sig_status_sidebar.pack(anchor="w", padx=24, pady=(0, 8))

        ttk.Label(
            sidebar,
            text="Luồng sử dụng:\n1. Sinh khóa\n2. Nhập văn bản hoặc chọn file\n3. Ký dữ liệu\n4. Chọn chữ ký và xác minh",
            style="SidebarText.TLabel",
            wraplength=195,
            justify="left"
        ).pack(anchor="w", padx=24, pady=(30, 0))

        content = ttk.Frame(main, style="Root.TFrame")
        content.pack(side="left", fill="both", expand=True, padx=26, pady=24)

        header = ttk.Frame(content, style="Root.TFrame")
        header.pack(fill="x", pady=(0, 18))

        title_box = tk.Frame(header, bg="#020617")
        title_box.pack(side="left", fill="x", expand=True)

        tk.Label(
            title_box,
            text="RSA Digital Signature Application",
            bg="#020617",
            fg="#f8fafc",
            font=("DejaVu Sans", 22, "bold")
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Ký số file/văn bản bằng private key và xác minh bằng public key.",
            bg="#020617",
            fg="#94a3b8",
            font=("DejaVu Sans", 10)
        ).pack(anchor="w", pady=(4, 0))

        # ===================== KEY CARD =====================
        key_frame = ttk.LabelFrame(
            content,
            text="1. Sinh cặp khóa RSA",
            style="Card.TLabelframe",
            padding=14
        )
        key_frame.pack(fill="x", pady=(0, 14))

        key_frame.columnconfigure(1, weight=1)

        ttk.Button(
            key_frame,
            text="Sinh khóa RSA",
            style="Primary.TButton",
            command=self.generate_key_pair
        ).grid(row=0, column=0, padx=(0, 12), pady=4)

        self.key_status_label = ttk.Label(
            key_frame,
            text="Chưa sinh khóa",
            style="Muted.TLabel"
        )
        self.key_status_label.grid(row=0, column=1, sticky="w")

        # ===================== TEXT CARD =====================
        text_frame = ttk.LabelFrame(
            content,
            text="2. Ký hoặc xác minh văn bản",
            style="Card.TLabelframe",
            padding=14
        )
        text_frame.pack(fill="both", expand=True, pady=(0, 14))

        tk.Label(
            text_frame,
            text="Nhập văn bản cần ký hoặc văn bản gốc cần xác minh:",
            bg="#0f172a",
            fg="#cbd5e1",
            font=("DejaVu Sans", 10)
        ).pack(anchor="w", pady=(0, 6))

        self.text_input = scrolledtext.ScrolledText(
            text_frame,
            height=8,
            font=("DejaVu Sans Mono", 10),
            relief="flat",
            borderwidth=0,
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#020617",
            padx=12,
            pady=10
        )
        self.text_input.pack(fill="both", expand=True)

        text_actions = tk.Frame(text_frame, bg="#0f172a")
        text_actions.pack(fill="x", pady=(12, 0))

        ttk.Button(
            text_actions,
            text="Ký văn bản",
            style="Success.TButton",
            command=self.sign_text
        ).pack(side="left", padx=(0, 10))

        ttk.Button(
            text_actions,
            text="Xác minh văn bản",
            style="Primary.TButton",
            command=self.verify_text
        ).pack(side="left")

        # ===================== FILE CARD =====================
        file_frame = ttk.LabelFrame(
            content,
            text="3. Ký file / xác minh file",
            style="Card.TLabelframe",
            padding=14
        )
        file_frame.pack(fill="x", pady=(0, 14))

        file_frame.columnconfigure(1, weight=1)

        ttk.Button(
            file_frame,
            text="Chọn file gốc",
            style="Ghost.TButton",
            command=self.choose_file
        ).grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")

        self.file_label = ttk.Label(
            file_frame,
            text="Chưa chọn file",
            style="Muted.TLabel"
        )
        self.file_label.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        ttk.Button(
            file_frame,
            text="Ký file",
            style="Success.TButton",
            command=self.sign_file
        ).grid(row=0, column=2, padx=(0, 8), pady=5)

        ttk.Button(
            file_frame,
            text="Chọn chữ ký .sig",
            style="Ghost.TButton",
            command=self.choose_signature
        ).grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")

        self.signature_label = ttk.Label(
            file_frame,
            text="Chưa chọn chữ ký",
            style="Muted.TLabel"
        )
        self.signature_label.grid(row=1, column=1, sticky="ew", padx=(0, 10))

        ttk.Button(
            file_frame,
            text="Xác minh file",
            style="Danger.TButton",
            command=self.verify_file
        ).grid(row=1, column=2, padx=(0, 8), pady=5)

        # ===================== RESULT CARD =====================
        result_frame = ttk.LabelFrame(
            content,
            text="4. Kết quả",
            style="Card.TLabelframe",
            padding=16
        )
        result_frame.pack(fill="x")

        self.result_label = ttk.Label(
            result_frame,
            text="Kết quả: Đang chờ thao tác",
            style="Status.TLabel"
        )
        self.result_label.pack(anchor="w")

    # ============================================================
    # HELPER
    # ============================================================
    def set_result(self, text, color="#2563eb"):
        self.result_label.config(text=text, foreground=color)

    def shorten_path(self, path, max_len=68):
        if not path:
            return ""
        if len(path) <= max_len:
            return path
        return "..." + path[-max_len:]

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
                foreground="#15803d"
            )
            self.key_status_sidebar.config(text="● Đã có khóa RSA", foreground="#86efac")
            self.set_result("Kết quả: Sinh khóa RSA thành công", "#15803d")

            messagebox.showinfo(
                "Thành công",
                "Đã sinh cặp khóa RSA thành công!"
            )

        except Exception as e:
            self.set_result("Kết quả: Sinh khóa thất bại", "#dc2626")
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
            display_path = self.shorten_path(path)
            self.file_label.config(text=display_path, foreground="#e5e7eb")
            self.file_status_sidebar.config(text=f"● File: {os.path.basename(path)}", foreground="#bfdbfe")

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
            display_path = self.shorten_path(path)
            self.signature_label.config(text=display_path, foreground="#e5e7eb")
            self.sig_status_sidebar.config(text=f"● Sig: {os.path.basename(path)}", foreground="#bfdbfe")

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
                self.set_result("Kết quả: Ký văn bản thành công", "#15803d")

                messagebox.showinfo(
                    "Thành công",
                    f"Đã ký văn bản thành công!\n\nFile chữ ký:\n{save_path}"
                )

        except Exception as e:
            self.set_result("Kết quả: Ký văn bản thất bại", "#dc2626")
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
                self.set_result("Kết quả: Ký file thành công", "#15803d")

                messagebox.showinfo(
                    "Thành công",
                    f"Đã ký file thành công!\n\nFile chữ ký:\n{save_path}"
                )

        except Exception as e:
            self.set_result("Kết quả: Ký file thất bại", "#dc2626")
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
                self.set_result("Kết quả: Chữ ký file HỢP LỆ", "#15803d")
                messagebox.showinfo(
                    "Xác minh thành công",
                    "Chữ ký hợp lệ.\n\nFile chưa bị thay đổi và đúng public key."
                )
            else:
                self.set_result("Kết quả: Chữ ký file KHÔNG HỢP LỆ", "#dc2626")
                messagebox.showerror(
                    "Xác minh thất bại",
                    "Chữ ký không hợp lệ.\n\nCó thể file đã bị sửa, chữ ký sai hoặc dùng sai public key."
                )

        except Exception as e:
            self.set_result("Kết quả: Lỗi xác minh file", "#dc2626")
            messagebox.showerror(
                "Lỗi",
                f"Không thể xác minh chữ ký:\n{e}"
            )

    # ============================================================
    # XÁC MINH VĂN BẢN
    # ============================================================
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
                self.set_result("Kết quả: Văn bản HỢP LỆ", "#15803d")
                messagebox.showinfo(
                    "Xác minh thành công",
                    "Chữ ký hợp lệ.\n\nVăn bản chưa bị thay đổi."
                )
            else:
                self.set_result("Kết quả: Văn bản KHÔNG HỢP LỆ", "#dc2626")
                messagebox.showerror(
                    "Xác minh thất bại",
                    "Chữ ký không hợp lệ.\n\nCó thể văn bản đã bị sửa hoặc dùng sai chữ ký."
                )

        except Exception as e:
            self.set_result("Kết quả: Lỗi xác minh văn bản", "#dc2626")
            messagebox.showerror("Lỗi", f"Không thể xác minh văn bản:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = RSASignatureApp(root)
    root.mainloop()