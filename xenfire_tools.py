#!/usr/bin/env python3
"""Xenfire Tools - gated login/signup, QR mobile signup, IPA installer"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, json, os, hashlib, binascii, datetime, socket, secrets, re
import device_backend as backend

from flask import Flask, request, render_template_string
import qrcode
from PIL import Image, ImageTk

APP_DIR = os.path.expanduser("~/.xenfire_tools")
ACCOUNTS_FILE = os.path.join(APP_DIR, "accounts.json")
MIN_AGE = 14
SERVER_PORT = 5050
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

BG = "#121212"
PANEL = "#1b1b1f"
ACCENT = "#ff5e3a"
ACCENT_DARK = "#c9431f"
TEXT = "#eaeaea"
SUBTEXT = "#9a9a9a"
ENTRY_BG = "#222227"
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_SUB = ("Segoe UI", 10)
FONT_BODY = ("Segoe UI", 10)
FONT_BTN = ("Segoe UI", 10, "bold")


# ---------------------------------------------------------------------------
# Storage / account logic
# ---------------------------------------------------------------------------
def _ensure_store():
    os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, "w") as f:
            json.dump({}, f)

def _load_accounts():
    _ensure_store()
    with open(ACCOUNTS_FILE, "r") as f:
        return json.load(f)

def _save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def _hash_value(value, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 100_000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def _verify_value(value, salt_hex, hash_hex):
    salt = binascii.unhexlify(salt_hex)
    _, test_hash = _hash_value(value, salt)
    return test_hash == hash_hex

def calculate_age(birthdate):
    today = datetime.date.today()
    return today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))

def validate_signup(username, email, password, security_q, security_a, birthdate):
    accounts = _load_accounts()
    if not username:
        return False, "Username is required."
    if username in accounts:
        return False, "That username is already taken."
    if not EMAIL_RE.match(email or ""):
        return False, "Enter a valid email address."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    if not security_q.strip() or not security_a.strip():
        return False, "Security question and answer are required."
    if calculate_age(birthdate) < MIN_AGE:
        return False, f"You must be {MIN_AGE} or older to create an account."
    return True, None

def create_account(username, email, password, security_q, security_a, birthdate):
    ok, err = validate_signup(username, email, password, security_q, security_a, birthdate)
    if not ok:
        return False, err
    accounts = _load_accounts()
    pw_salt, pw_hash = _hash_value(password)
    sa_salt, sa_hash = _hash_value(security_a.strip().lower())
    accounts[username] = {
        "email": email,
        "pw_salt": pw_salt, "pw_hash": pw_hash,
        "security_q": security_q.strip(),
        "sa_salt": sa_salt, "sa_hash": sa_hash,
        "birthdate": birthdate.isoformat(),
        "age_verified": True,
        "created": datetime.datetime.now().isoformat(),
    }
    _save_accounts(accounts)
    return True, "Account created successfully."

def check_login(username, password):
    accounts = _load_accounts()
    acc = accounts.get(username)
    if not acc:
        return False
    return _verify_value(password, acc["pw_salt"], acc["pw_hash"])

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Flask server (phone-side signup, reached via QR code)
# ---------------------------------------------------------------------------
flask_app = Flask(__name__)
SESSIONS = {}  # token -> {"status": "pending"/"done", "message": str, "username": str}

SIGNUP_PAGE = """
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xenfire Tools - Create Account</title>
<style>
body{font-family:-apple-system,Segoe UI,sans-serif;background:#121212;color:#eaeaea;margin:0;padding:24px;}
h1{color:#ff5e3a;font-size:22px;}
h2{font-size:15px;color:#ff5e3a;margin-top:28px;border-top:1px solid #333;padding-top:18px;}
label{display:block;margin-top:14px;font-size:14px;color:#9a9a9a;}
input{width:100%;padding:12px;margin-top:6px;border-radius:8px;border:1px solid #333;
  background:#222227;color:#eaeaea;font-size:16px;box-sizing:border-box;}
.checkrow{display:flex;align-items:center;margin-top:16px;}
.checkrow input{margin-right:10px;width:18px;height:18px;}
button{margin-top:26px;width:100%;padding:14px;background:#ff5e3a;color:white;
  border:none;border-radius:8px;font-size:16px;font-weight:bold;}
.error{color:#ff6b6b;margin-top:14px;}
</style></head><body>
<h1>Create Your Xenfire Account</h1>
<form method="POST">
  <h2>Section 1 — Account Info</h2>
  <label>Username</label><input type="text" name="username" required>
  <label>Email</label><input type="email" name="email" required>

  <h2>Section 2 — Age Verification</h2>
  <label>Date of birth</label><input type="date" name="dob" required>
  <div class="checkrow"><input type="checkbox" name="age_confirm" required> I confirm I am {{min_age}}+ years old</div>
  <div class="checkrow"><input type="checkbox" name="terms" required> I agree to the Terms of Use</div>

  <h2>Section 3 — Security</h2>
  <label>Password</label><input type="password" name="password" required>
  <label>Confirm password</label><input type="password" name="password2" required>
  <label>Security question (e.g. "First pet's name?")</label><input type="text" name="security_q" required>
  <label>Answer</label><input type="text" name="security_a" required>

  {% if error %}<div class="error">{{error}}</div>{% endif %}
  <button type="submit">Create Account</button>
</form>
</body></html>
"""

DONE_PAGE = """
<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,sans-serif;background:#121212;color:#eaeaea;
text-align:center;padding-top:80px;}h1{color:#4caf50;}</style></head>
<body><h1>✓ Account Created</h1><p>Close this tab and return to Xenfire Tools.</p></body></html>
"""

@flask_app.route("/signup/<token>", methods=["GET", "POST"])
def signup(token):
    session = SESSIONS.get(token)
    if not session or session["status"] != "pending":
        return "This signup link is invalid or has already been used.", 400

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        dob_str = request.form.get("dob", "")
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        security_q = request.form.get("security_q", "")
        security_a = request.form.get("security_a", "")
        age_confirm = request.form.get("age_confirm")
        terms = request.form.get("terms")

        try:
            birthdate = datetime.date.fromisoformat(dob_str)
        except ValueError:
            birthdate = None

        if not birthdate:
            error = "Enter a valid date of birth."
        elif birthdate > datetime.date.today():
            error = "Date of birth can't be in the future."
        elif not age_confirm or not terms:
            error = "Please confirm your age and agree to the Terms of Use."
        elif password != password2:
            error = "Passwords do not match."
        else:
            ok, msg = create_account(username, email, password, security_q, security_a, birthdate)
            if ok:
                SESSIONS[token] = {"status": "done", "message": f"Account '{username}' created.", "username": username}
                return DONE_PAGE
            error = msg

    return render_template_string(SIGNUP_PAGE, error=error, min_age=MIN_AGE)


def start_server_once():
    """Start the Flask dev server once, in a background thread, with the
    reverse-DNS-lookup delay disabled (fixes multi-second QR load times)."""
    if not getattr(start_server_once, "_started", False):
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.address_string = lambda self: self.client_address[0]

        threading.Thread(
            target=lambda: flask_app.run(
                host="0.0.0.0", port=SERVER_PORT, use_reloader=False, threaded=True
            ),
            daemon=True
        ).start()
        start_server_once._started = True


# ---------------------------------------------------------------------------
# Tkinter styling helpers
# ---------------------------------------------------------------------------
def style_entry(entry):
    entry.config(bg=ENTRY_BG, fg=TEXT, insertbackground=TEXT, relief="flat",
                  highlightthickness=1, highlightbackground="#333", highlightcolor=ACCENT)

def accent_button(parent, text, command, width=20):
    return tk.Button(parent, text=text, command=command, font=FONT_BTN, bg=ACCENT, fg="white",
                      activebackground=ACCENT_DARK, activeforeground="white", relief="flat",
                      bd=0, cursor="hand2", width=width, pady=8)

def section_label(parent, text):
    tk.Label(parent, text=text, font=("Segoe UI", 11, "bold"), bg=PANEL, fg=ACCENT).pack(anchor="w", pady=(18, 4))

def labeled_entry(parent, label_text, show=None):
    tk.Label(parent, text=label_text, font=FONT_BODY, bg=PANEL, fg=TEXT).pack(anchor="w", pady=(6, 2))
    var = tk.StringVar()
    entry = tk.Entry(parent, textvariable=var, show=show)
    style_entry(entry)
    entry.pack(fill="x", ipady=6)
    return var


# ---------------------------------------------------------------------------
# Scrollable container (used by login + signup screens)
# ---------------------------------------------------------------------------
class ScrollableFrame(tk.Frame):
    """A frame with a vertical scrollbar and mousewheel/trackpad support.
    Put your content inside .body."""
    def __init__(self, parent, bg=PANEL):
        super().__init__(parent, bg=bg)

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vscroll = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vscroll.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vscroll.pack(side="right", fill="y")

        self.body = tk.Frame(self.canvas, bg=bg)
        self.body_window = self.canvas.create_window((0, 0), window=self.body, anchor="n")

        self.body.bind("<Configure>", self._on_body_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.bind("<Enter>", lambda e: self._bind_mousewheel())
        self.canvas.bind("<Leave>", lambda e: self._unbind_mousewheel())

    def _on_body_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.body_window, width=event.width)

    def _bind_mousewheel(self):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _unbind_mousewheel(self):
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event):
        if event.num == 4:
            self.canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            self.canvas.yview_scroll(3, "units")
        else:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120) * 3), "units")


# ---------------------------------------------------------------------------
# In-app (manual) signup form
# ---------------------------------------------------------------------------
class ManualSignupFrame(tk.Frame):
    def __init__(self, parent, on_success, on_back):
        super().__init__(parent, bg=PANEL)
        self.on_success = on_success

        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)

        wrap = tk.Frame(scroll.body, bg=PANEL)
        wrap.pack(fill="x", padx=40, pady=20)

        tk.Label(wrap, text="Create Account", font=FONT_TITLE, bg=PANEL, fg=TEXT).pack(anchor="w")

        section_label(wrap, "Section 1 — Account Info")
        self.username_var = labeled_entry(wrap, "Username")
        self.email_var = labeled_entry(wrap, "Email")

        section_label(wrap, "Section 2 — Age Verification")
        dob_frame = tk.Frame(wrap, bg=PANEL)
        dob_frame.pack(anchor="w", pady=(6, 0))
        self.month_var, self.day_var, self.year_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, var, w in (("MM", self.month_var, 4), ("DD", self.day_var, 4), ("YYYY", self.year_var, 6)):
            col = tk.Frame(dob_frame, bg=PANEL)
            col.pack(side="left", padx=4)
            tk.Label(col, text=label, font=("Segoe UI", 8), bg=PANEL, fg=SUBTEXT).pack()
            e = tk.Entry(col, textvariable=var, width=w, justify="center")
            style_entry(e)
            e.pack()

        self.age_confirm_var = tk.BooleanVar()
        tk.Checkbutton(wrap, text=f"I confirm I am {MIN_AGE}+ years old", variable=self.age_confirm_var,
                        bg=PANEL, fg=TEXT, selectcolor=ENTRY_BG, activebackground=PANEL,
                        activeforeground=TEXT, font=FONT_BODY).pack(anchor="w", pady=(10, 0))
        self.terms_var = tk.BooleanVar()
        tk.Checkbutton(wrap, text="I agree to the Terms of Use", variable=self.terms_var,
                        bg=PANEL, fg=TEXT, selectcolor=ENTRY_BG, activebackground=PANEL,
                        activeforeground=TEXT, font=FONT_BODY).pack(anchor="w")

        section_label(wrap, "Section 3 — Security")
        self.password_var = labeled_entry(wrap, "Password", show="•")
        self.password2_var = labeled_entry(wrap, "Confirm password", show="•")
        self.sq_var = labeled_entry(wrap, "Security question")
        self.sa_var = labeled_entry(wrap, "Answer")

        self.error_label = tk.Label(wrap, text="", fg="#ff6b6b", bg=PANEL, font=FONT_SUB, wraplength=500, justify="left")
        self.error_label.pack(pady=(14, 0), anchor="w")

        btn_row = tk.Frame(wrap, bg=PANEL)
        btn_row.pack(fill="x", pady=(16, 30))
        accent_button(btn_row, "Create Account", self._submit, width=20).pack(side="left")
        tk.Button(btn_row, text="Back to Login", command=on_back, bg=PANEL, fg=SUBTEXT,
                  relief="flat", cursor="hand2").pack(side="left", padx=15)

    def _submit(self):
        try:
            birthdate = datetime.date(int(self.year_var.get()), int(self.month_var.get()), int(self.day_var.get()))
        except (ValueError, TypeError):
            self.error_label.config(text="Enter a valid date of birth.")
            return
        if birthdate > datetime.date.today():
            self.error_label.config(text="Date of birth can't be in the future.")
            return
        if not self.age_confirm_var.get() or not self.terms_var.get():
            self.error_label.config(text="Please confirm your age and agree to the Terms of Use.")
            return
        if self.password_var.get() != self.password2_var.get():
            self.error_label.config(text="Passwords do not match.")
            return

        ok, msg = create_account(
            self.username_var.get().strip(), self.email_var.get().strip(),
            self.password_var.get(), self.sq_var.get(), self.sa_var.get(), birthdate
        )
        if ok:
            messagebox.showinfo("Xenfire Tools", msg)
            self.on_success(self.username_var.get().strip())
        else:
            self.error_label.config(text=msg)


# ---------------------------------------------------------------------------
# QR signup popup
# ---------------------------------------------------------------------------
class QRAccountWindow(tk.Toplevel):
    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.on_success = on_success
        self.title("Create Account — Scan with Phone")
        self.geometry("380x520")
        self.configure(bg=PANEL)
        self.resizable(False, False)
        self.grab_set()

        start_server_once()
        self.token = secrets.token_urlsafe(12)
        SESSIONS[self.token] = {"status": "pending", "message": ""}

        ip = get_local_ip()
        url = f"http://{ip}:{SERVER_PORT}/signup/{self.token}"

        tk.Label(self, text="Scan to Create Account", font=FONT_TITLE, bg=PANEL, fg=TEXT).pack(pady=(20, 5))
        tk.Label(self, text="Your phone must be on the same Wi-Fi network", font=FONT_SUB,
                 bg=PANEL, fg=SUBTEXT, wraplength=300, justify="center").pack(pady=(0, 15))

        qr_img = qrcode.make(url).resize((260, 260))
        self.qr_photo = ImageTk.PhotoImage(qr_img)
        tk.Label(self, image=self.qr_photo, bg=PANEL).pack()

        tk.Label(self, text=url, font=("Consolas", 8), bg=PANEL, fg=SUBTEXT, wraplength=320).pack(pady=10)

        self.status_label = tk.Label(self, text="Waiting for phone...", font=FONT_BODY, bg=PANEL, fg=ACCENT)
        self.status_label.pack(pady=10)

        if ip.startswith("100.115.92."):
            tk.Label(self, text="⚠ This looks like a Crostini-internal IP.\n"
                                 "Your phone may not be able to reach it —\n"
                                 "see Settings > Linux > Port forwarding.",
                     font=("Segoe UI", 8), bg=PANEL, fg="#ffb347", justify="center").pack(pady=(0, 10))

        self.after(1000, self._poll)

    def _poll(self):
        session = SESSIONS.get(self.token)
        if session and session["status"] == "done":
            self.status_label.config(text=session["message"], fg="#4caf50")
            self.destroy()
            self.on_success(session.get("username"))
            return
        self.after(1000, self._poll)


# ---------------------------------------------------------------------------
# Login screen
# ---------------------------------------------------------------------------
class LoginFrame(tk.Frame):
    def __init__(self, parent, on_login_success):
        super().__init__(parent, bg=PANEL)
        self.on_login_success = on_login_success

        scroll = ScrollableFrame(self)
        scroll.pack(fill="both", expand=True)

        outer = tk.Frame(scroll.body, bg=PANEL)
        outer.pack(fill="both", expand=True, pady=60)

        wrap = tk.Frame(outer, bg=PANEL)
        wrap.pack()

        tk.Label(wrap, text="Xenfire Tools", font=("Segoe UI", 24, "bold"), bg=PANEL, fg=ACCENT).pack(pady=(10, 2))
        tk.Label(wrap, text="Sign in to continue", font=FONT_SUB, bg=PANEL, fg=SUBTEXT).pack(pady=(0, 20))

        self.username_var = labeled_entry(wrap, "Username")
        self.password_var = labeled_entry(wrap, "Password", show="•")

        self.error_label = tk.Label(wrap, text="", fg="#ff6b6b", bg=PANEL, font=FONT_SUB)
        self.error_label.pack(pady=(10, 0))

        accent_button(wrap, "Sign In", self._try_login, width=24).pack(pady=(18, 8))
        tk.Button(wrap, text="Create Account (in-app)", command=self._go_manual_signup,
                  bg=PANEL, fg=SUBTEXT, relief="flat", cursor="hand2").pack()
        tk.Button(wrap, text="Create Account (scan QR with phone)", command=self._go_qr_signup,
                  bg=PANEL, fg=SUBTEXT, relief="flat", cursor="hand2").pack(pady=(4, 0))

    def _try_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if check_login(username, password):
            self.on_login_success(username)
        else:
            self.error_label.config(text="Invalid username or password.")

    def _go_manual_signup(self):
        self.master.show_manual_signup()

    def _go_qr_signup(self):
        QRAccountWindow(self.master, on_success=lambda uname: self.master.show_login(prefill=uname))


# ---------------------------------------------------------------------------
# Root app
# ---------------------------------------------------------------------------
class XenfireTools(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Xenfire Tools")
        self.geometry("1000x720")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(640, 480)

        # Open maximized; falls back gracefully if the window manager
        # doesn't support "-zoomed" (some Linux WMs use "zoomed" without dash)
        try:
            self.state("zoomed")
        except tk.TclError:
            try:
                self.attributes("-zoomed", True)
            except tk.TclError:
                pass

        self.current_user = None
        self.gate_frame = None
        self.show_login()

    def _clear_gate(self):
        for w in self.winfo_children():
            w.destroy()
        self.gate_frame = None

    def show_login(self, prefill=None):
        self._clear_gate()
        self.gate_frame = LoginFrame(self, self._on_login_success)
        self.gate_frame.pack(fill="both", expand=True)
        if prefill:
            self.gate_frame.username_var.set(prefill)

    def show_manual_signup(self):
        self._clear_gate()
        self.gate_frame = ManualSignupFrame(
            self,
            on_success=lambda uname: self.show_login(prefill=uname),
            on_back=self.show_login
        )
        self.gate_frame.pack(fill="both", expand=True)

    def _on_login_success(self, username):
        self.current_user = username
        self._clear_gate()
        self._build_main_app()

    # ---- Main app (only reachable after login) ----
    def _build_main_app(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", pady=(15, 5), padx=20)
        tk.Label(header, text="Xenfire Tools", font=FONT_TITLE, bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(header, text=f"Signed in as {self.current_user}", font=FONT_SUB, bg=BG, fg=SUBTEXT).pack(side="left", padx=15)
        tk.Button(header, text="Log Out", command=self._logout, bg=PANEL, fg=TEXT,
                  relief="flat", cursor="hand2").pack(side="right")

        self.status_var = tk.StringVar(value="No device detected")
        status_bar = tk.Label(self, textvariable=self.status_var, anchor="w", bg="#000", fg="#0f0", font=("Consolas", 9))
        status_bar.pack(fill="x", side="bottom")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=TEXT, padding=(15, 8), font=FONT_BODY)
        style.map("TNotebook.Tab", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        style.configure("TFrame", background=PANEL)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=15, pady=10)

        notebook.add(self._build_install_tab(notebook), text="Install IPA")
        notebook.add(self._build_coming_soon_tab(notebook, "Passkey Tools"), text="Passkeys")
        notebook.add(self._build_coming_soon_tab(notebook, "Email Tools"), text="Email")
        notebook.add(self._build_coming_soon_tab(notebook, "More Tools"), text="More")

        self._refresh_status()

    def _logout(self):
        self.current_user = None
        self._clear_gate()
        self.show_login()

    def _build_coming_soon_tab(self, parent, label_text):
        frame = ttk.Frame(parent)
        tk.Label(frame, text=label_text, font=("Segoe UI", 14, "bold"), bg=PANEL, fg=TEXT).pack(pady=(40, 5))
        tk.Label(frame, text="Coming soon.", font=FONT_SUB, bg=PANEL, fg=SUBTEXT).pack()
        return frame

    def _build_install_tab(self, parent):
        frame = ttk.Frame(parent)
        tk.Label(frame, text="IPA Installer", font=("Segoe UI", 14, "bold"), bg=PANEL, fg=TEXT).pack(pady=(15, 10))

        device_box = tk.Frame(frame, bg=ENTRY_BG, bd=0)
        device_box.pack(fill="x", padx=20, pady=5)
        self.device_info_label = tk.Label(device_box, text="Checking...", justify="left", anchor="w",
                                           bg=ENTRY_BG, fg=TEXT, font=("Consolas", 9), padx=10, pady=10)
        self.device_info_label.pack(fill="x")

        tk.Button(frame, text="Refresh Device", command=self._refresh_status,
                  bg=PANEL, fg=TEXT, relief="flat", font=FONT_BODY, cursor="hand2").pack(pady=8)

        self.ipa_path_var = tk.StringVar()
        path_frame = tk.Frame(frame, bg=PANEL)
        path_frame.pack(fill="x", padx=20, pady=10)
        p_entry = tk.Entry(path_frame, textvariable=self.ipa_path_var, state="readonly")
        style_entry(p_entry)
        p_entry.pack(side="left", fill="x", expand=True, ipady=6)
        tk.Button(path_frame, text="Browse...", command=self._choose_ipa,
                  bg=ENTRY_BG, fg=TEXT, relief="flat", cursor="hand2").pack(side="left", padx=8)

        accent_button(frame, "Install IPA", self._install_clicked, width=20).pack(pady=10)

        self.log_box = tk.Text(frame, height=10, bg="black", fg="#0f0", relief="flat", font=("Consolas", 9))
        self.log_box.pack(fill="both", expand=True, padx=20, pady=10)
        return frame

    def _refresh_status(self):
        connected = backend.device_connected()
        if connected:
            info = backend.get_device_info()
            text = "\n".join(f"{k}: {v}" for k, v in info.items())
            self.device_info_label.config(text=text)
            self.status_var.set("Device connected")
        else:
            self.device_info_label.config(text="No device found. Connect via USB and trust this computer.")
            self.status_var.set("No device detected")

    def _choose_ipa(self):
        path = filedialog.askopenfilename(filetypes=[("IPA files", "*.ipa")])
        if path:
            self.ipa_path_var.set(path)

    def _log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def _install_clicked(self):
        path = self.ipa_path_var.get()
        if not path:
            messagebox.showwarning("Xenfire Tools", "Choose an .ipa file first.")
            return
        self.log_box.delete("1.0", "end")
        self._log(f"Installing {path} ...")
        threading.Thread(target=self._run_install, args=(path,), daemon=True).start()

    def _run_install(self, path):
        ok, output = backend.install_ipa(path, progress_callback=self._log)
        if ok:
            self._log("Install finished successfully.")
        else:
            self._log("Install failed:")
            self._log(output)


if __name__ == "__main__":
    app = XenfireTools()
    app.mainloop()
