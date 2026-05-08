from __future__ import annotations
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import pyotp
from client.session import Client, ClientError
from common.constants import HOST, PORT

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Mini-Blockchain")
        self.geometry("840x640")
        self.client: Client | None = None
        self._last_totp_secret: str | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Host:").pack(side="left")
        self.host_var = tk.StringVar(value=HOST)
        ttk.Entry(top, textvariable=self.host_var, width=14).pack(side="left", padx=4)
        ttk.Label(top, text="Porta:").pack(side="left")
        self.port_var = tk.StringVar(value=str(PORT))
        ttk.Entry(top, textvariable=self.port_var, width=6).pack(side="left", padx=4)
        self.connect_btn = ttk.Button(top, text="Conectar", command=self._on_connect)
        self.connect_btn.pack(side="left", padx=4)
        self.status_var = tk.StringVar(value="desconectado")
        ttk.Label(top, textvariable=self.status_var, foreground="#555").pack(side="left", padx=8)

        self.body = ttk.Frame(self, padding=8)
        self.body.pack(fill="both", expand=True)

        self.auth_frame = self._build_auth_frame(self.body)
        self.main_frame = self._build_main_frame(self.body)
        self.auth_frame.pack(fill="both", expand=True)

    def _build_auth_frame(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True)
        nb.add(self._build_register_tab(nb), text="Cadastrar")
        nb.add(self._build_login_tab(nb), text="Login")
        return frame

    def _build_register_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(parent, padding=12)
        self.reg_user = tk.StringVar()
        self.reg_pw1 = tk.StringVar()
        self.reg_pw2 = tk.StringVar()
        ttk.Label(f, text="Usuário:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.reg_user, width=28).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Senha:").grid(row=1, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.reg_pw1, width=28, show="*").grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Confirme:").grid(row=2, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.reg_pw2, width=28, show="*").grid(row=2, column=1, sticky="w", pady=2)
        self.reg_btn = ttk.Button(f, text="Cadastrar", command=self._on_register)
        self.reg_btn.grid(row=3, column=1, sticky="w", pady=8)
        ttk.Label(
            f,
            text="Após cadastrar, o segredo TOTP aparece em uma caixa de diálogo.\nUse um app autenticador ou o botão 'Gerar TOTP' na aba Login.",
            foreground="#555",
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 0))
        return f

    def _build_login_tab(self, parent: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(parent, padding=12)
        self.log_user = tk.StringVar()
        self.log_pw = tk.StringVar()
        self.log_totp = tk.StringVar()
        ttk.Label(f, text="Usuário:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.log_user, width=28).grid(row=0, column=1, sticky="w", pady=2)
        ttk.Label(f, text="Senha:").grid(row=1, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.log_pw, width=28, show="*").grid(row=1, column=1, sticky="w", pady=2)
        ttk.Label(f, text="TOTP:").grid(row=2, column=0, sticky="w")
        ttk.Entry(f, textvariable=self.log_totp, width=10).grid(row=2, column=1, sticky="w", pady=2)
        ttk.Button(f, text="Gerar TOTP (último cadastro desta sessão)", command=self._on_fill_totp).grid(
            row=2, column=2, padx=6, sticky="w"
        )
        self.login_btn = ttk.Button(f, text="Login", command=self._on_login)
        self.login_btn.grid(row=3, column=1, sticky="w", pady=8)
        return f

    def _build_main_frame(self, parent: ttk.Frame) -> ttk.Frame:
        frame = ttk.Frame(parent)
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 6))
        self.who_var = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.who_var, font=("TkDefaultFont", 11, "bold")).pack(side="left")
        ttk.Button(header, text="Logout", command=self._on_logout).pack(side="right")

        nb = ttk.Notebook(frame)
        nb.pack(fill="both", expand=True)

        add = ttk.Frame(nb, padding=8)
        ttk.Label(add, text="Dados do bloco (serão cifrados com AES-GCM aqui no cliente):").pack(anchor="w")
        self.add_text = scrolledtext.ScrolledText(add, height=8, wrap="word")
        self.add_text.pack(fill="both", expand=True)
        ttk.Button(add, text="Adicionar bloco", command=self._on_add_block).pack(anchor="e", pady=6)
        nb.add(add, text="Adicionar bloco")

        list_tab = ttk.Frame(nb, padding=8)
        btns = ttk.Frame(list_tab)
        btns.pack(fill="x")
        ttk.Button(btns, text="Atualizar e validar cadeia", command=self._on_refresh).pack(side="left")
        ttk.Button(btns, text="Decifrar meus blocos", command=self._on_decrypt_mine).pack(side="left", padx=6)
        self.chain_status = tk.StringVar(value="cadeia: —")
        ttk.Label(btns, textvariable=self.chain_status, foreground="#333").pack(side="left", padx=12)

        cols = ("index", "owner", "timestamp", "hash", "plaintext")
        self.tree = ttk.Treeview(list_tab, columns=cols, show="headings", height=14)
        for col, w in zip(cols, (50, 90, 180, 150, 300)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=6)
        nb.add(list_tab, text="Cadeia")

        tamper = ttk.Frame(nb, padding=8)
        ttk.Label(tamper, text="Ferramenta de demonstração: adultera um bloco no servidor.", foreground="#555").grid(
            row=0, column=0, columnspan=5, sticky="w", pady=(0, 8)
        )
        ttk.Label(tamper, text="Índice:").grid(row=1, column=0, sticky="w")
        self.tamper_idx = tk.StringVar(value="1")
        ttk.Entry(tamper, textvariable=self.tamper_idx, width=6).grid(row=1, column=1, sticky="w")
        ttk.Label(tamper, text="Modo:").grid(row=1, column=2, sticky="w", padx=(12, 4))
        self.tamper_mode = tk.StringVar(value="ciphertext")
        ttk.Combobox(
            tamper,
            textvariable=self.tamper_mode,
            values=["ciphertext", "prev_hash"],
            width=14,
            state="readonly",
        ).grid(row=1, column=3, sticky="w")
        ttk.Button(tamper, text="Adulterar bloco", command=self._on_tamper).grid(row=1, column=4, padx=8)
        ttk.Label(
            tamper,
            text="Depois de adulterar volte à aba 'Cadeia' e clique em 'Atualizar', a validação vai falhar.",
            foreground="#555",
        ).grid(row=2, column=0, columnspan=5, sticky="w", pady=12)
        nb.add(tamper, text="Adulterar")

        logs = ttk.Frame(nb, padding=8)
        ttk.Button(logs, text="Atualizar log", command=self._on_logs).pack(anchor="w")
        self.logs_text = scrolledtext.ScrolledText(logs, height=20, wrap="none")
        self.logs_text.pack(fill="both", expand=True, pady=6)
        nb.add(logs, text="Auditoria")

        return frame

    def _on_connect(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
            self.status_var.set("desconectado")
            self.connect_btn.configure(text="Conectar")
            self._show_auth()
            return
        try:
            self.client = Client(self.host_var.get().strip(), int(self.port_var.get()))
            self.client.connect()
        except Exception as exc:
            messagebox.showerror("Conexão", str(exc))
            self.client = None
            return
        self.status_var.set(f"conectado a {self.host_var.get()}:{self.port_var.get()}")
        self.connect_btn.configure(text="Desconectar")

    def _require_connected(self) -> bool:
        if self.client is None:
            messagebox.showwarning("Conexão", "Conecte ao servidor primeiro.")
            return False
        return True

    def _require_logged(self) -> bool:
        if not self._require_connected():
            return False
        if self.client is None or self.client.session is None:
            messagebox.showwarning("Sessão", "Faça login primeiro.")
            return False
        return True

    def _run_async(self, label: str, button: ttk.Button | None, work, on_done) -> None:
        """Roda `work()` numa thread e chama `on_done(result_or_exc)` de volta na UI thread.

        PBKDF2 com 300k iterações bloqueia ~0.3–0.5 s; isso evita congelar a janela.
        """
        if button is not None:
            button.configure(state="disabled")
        prev_status = self.status_var.get()
        self.status_var.set(f"{prev_status} — {label}…")

        def runner() -> None:
            try:
                res = work()
                self.after(0, lambda: _finish(res, None))
            except Exception as exc:
                self.after(0, lambda e=exc: _finish(None, e))

        def _finish(result, exc):
            if button is not None:
                button.configure(state="normal")
            self.status_var.set(prev_status)
            on_done(result, exc)

        threading.Thread(target=runner, daemon=True).start()

    def _on_register(self) -> None:
        if not self._require_connected():
            return
        user = self.reg_user.get().strip()
        p1, p2 = self.reg_pw1.get(), self.reg_pw2.get()
        if not user or not p1:
            messagebox.showwarning("Cadastro", "Preencha usuário e senha.")
            return
        if p1 != p2:
            messagebox.showerror("Cadastro", "As senhas não conferem.")
            return

        def done(result, exc):
            if exc is not None:
                messagebox.showerror("Cadastro", str(exc))
                return
            secret, uri = result
            self._last_totp_secret = secret
            self.reg_pw1.set("")
            self.reg_pw2.set("")
            messagebox.showinfo(
                "Cadastro ok",
                f"Usuário '{user}' cadastrado.\n\n"
                f"Segredo TOTP (base32):\n{secret}\n\n"
                f"URI otpauth:\n{uri}\n\n"
                "Use este segredo em um app autenticador, ou clique em\n"
                "'Gerar TOTP' na aba Login (usa o segredo em memória).",
            )

        self._run_async("derivando PBKDF2", self.reg_btn, lambda: self.client.register(user, p1), done)

    def _on_fill_totp(self) -> None:
        if not self._last_totp_secret:
            messagebox.showinfo(
                "TOTP",
                "Nenhum segredo em memória nesta sessão. Cadastre um usuário ou gere o código\nno app autenticador.",
            )
            return
        self.log_totp.set(pyotp.TOTP(self._last_totp_secret).now())

    def _on_login(self) -> None:
        if not self._require_connected():
            return
        user = self.log_user.get().strip()
        pw = self.log_pw.get()
        code = self.log_totp.get().strip()
        if not user or not pw or not code:
            messagebox.showwarning("Login", "Preencha usuário, senha e TOTP.")
            return

        def done(result, exc):
            if exc is not None:
                messagebox.showerror("Login", str(exc))
                return
            sess = result
            self.log_pw.set("")
            self.log_totp.set("")
            self.who_var.set(f"Logado como: {sess.username}")
            self._show_main()
            self._on_refresh()

        self._run_async("derivando PBKDF2", self.login_btn, lambda: self.client.login(user, pw, code), done)

    def _on_logout(self) -> None:
        if self.client is not None:
            try:
                self.client.logout()
            except Exception:
                pass
        self.who_var.set("")
        self._show_auth()

    def _on_add_block(self) -> None:
        if not self._require_logged():
            return
        data = self.add_text.get("1.0", "end").rstrip("\n").encode("utf-8")
        if not data:
            return
        try:
            reply = self.client.add_block(data)
        except ClientError as exc:
            messagebox.showerror("Bloco", str(exc))
            return
        self.add_text.delete("1.0", "end")
        messagebox.showinfo("Bloco", f"Bloco #{reply['index']} adicionado.")
        self._on_refresh()

    def _on_refresh(self) -> None:
        if not self._require_logged():
            return
        try:
            reply = self.client.list_chain()
        except ClientError as exc:
            messagebox.showerror("Cadeia", str(exc))
            return
        self._populate_tree(reply["blocks"], {})
        self._set_chain_status(reply)

    def _on_decrypt_mine(self) -> None:
        if not self._require_logged():
            return
        try:
            reply = self.client.list_chain()
            decoded = {e["index"]: e for e in self.client.decrypt_mine(reply["blocks"])}
        except ClientError as exc:
            messagebox.showerror("Cadeia", str(exc))
            return
        self._populate_tree(reply["blocks"], decoded)
        self._set_chain_status(reply)

    def _set_chain_status(self, reply: dict) -> None:
        if reply["chain_ok"]:
            self.chain_status.set(f"cadeia OK ({len(reply['blocks'])} blocos)")
        else:
            self.chain_status.set(f"CADEIA INVÁLIDA — {reply.get('chain_error')}")

    def _populate_tree(self, blocks: list[dict], decoded: dict[int, dict]) -> None:
        self.tree.delete(*self.tree.get_children())
        for b in blocks:
            idx = int(b["index"])
            entry = decoded.get(idx)
            if entry is None:
                plaintext = ""
            elif entry.get("plaintext") is not None:
                plaintext = entry["plaintext"]
            elif "error" in entry:
                plaintext = f"!! {entry['error']}"
            else:
                plaintext = "(outro usuário — opaco)"
            self.tree.insert(
                "",
                "end",
                values=(idx, b["owner"], b["timestamp"], b["hash"][:22] + "…", plaintext),
            )

    def _on_tamper(self) -> None:
        if not self._require_logged():
            return
        try:
            idx = int(self.tamper_idx.get())
        except ValueError:
            messagebox.showerror("Adulterar", "Índice inválido.")
            return
        try:
            self.client.tamper(idx, self.tamper_mode.get())
        except ClientError as exc:
            messagebox.showerror("Adulterar", str(exc))
            return
        messagebox.showinfo(
            "Adulterar",
            f"Bloco {idx} adulterado (modo={self.tamper_mode.get()}).\nAbra a aba 'Cadeia' e clique em 'Atualizar'.",
        )

    def _on_logs(self) -> None:
        if not self._require_logged():
            return
        try:
            lines = self.client.logs(200)
        except ClientError as exc:
            messagebox.showerror("Logs", str(exc))
            return
        self.logs_text.delete("1.0", "end")
        self.logs_text.insert("1.0", "\n".join(lines))

    def _show_auth(self) -> None:
        self.main_frame.pack_forget()
        self.auth_frame.pack(fill="both", expand=True)

    def _show_main(self) -> None:
        self.auth_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

def main() -> None:
    App().mainloop()

if __name__ == "__main__":
    main()
