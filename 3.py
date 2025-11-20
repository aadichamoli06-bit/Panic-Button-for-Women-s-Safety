import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import datetime, json, requests, os, threading, hashlib, secrets, sys

# ------------------- CONFIG -------------------
BOT_TOKEN = "8385445878:AAEDrLNCuWeARbyVUAOdTJr2kg9WrjxTYn8"  # <-- replace
LOCATIONS_FILE = "locations.json"
CONTACTS_FILE = "contacts.json"
ALERTS_FILE = "alerts.json"
USERS_FILE = "users.json"
SESSION_FILE = "session.json"

# --- Modern Color Palette ---
BG = "#F8F9FA"
CARD = "#FFFFFF"
TEXT = "#212529"
SUBTEXT = "#6C757D"
PRIMARY = "#007BFF"     # Edit
SUCCESS = "#28A745"     # Add
DANGER = "#DC3545"      # Delete
PANIC = "#FF073A"       # PANIC (brighter red)
HEADER_BG = "#343A40"
BORDER = "#CED4DA"
ROLE_ADMIN = "Admin"
ROLE_OPERATOR = "Operator"

# ------------------- HELPERS: AUTH -------------------
def make_salt(n_bytes: int = 16) -> str:
    return secrets.token_hex(n_bytes)

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def get_users():
    return load_json(USERS_FILE, [])

def set_users(users):
    save_json(USERS_FILE, users)

def get_session():
    return load_json(SESSION_FILE, {})

def set_session(session_obj):
    save_json(SESSION_FILE, session_obj)

def clear_session():
    if os.path.exists(SESSION_FILE):
        try:
            os.remove(SESSION_FILE)
        except:
            pass

def find_user(username):
    users = get_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None

def verify_password(user_obj, password_plain):
    try:
        salt = user_obj["salt"]
        hashed = user_obj["password_hash"]
    except KeyError:
        # Legacy plain text support (if ever existed); migrate on successful login
        return user_obj.get("password") == password_plain
    return hash_password(password_plain, salt) == hashed

def migrate_legacy_password(user_obj, password_plain):
    # If legacy "password" exists, migrate to salted hash
    if "password" in user_obj and password_plain == user_obj["password"]:
        salt = make_salt()
        user_obj["salt"] = salt
        user_obj["password_hash"] = hash_password(password_plain, salt)
        del user_obj["password"]
        users = get_users()
        for i, u in enumerate(users):
            if u.get("username") == user_obj["username"]:
                users[i] = user_obj
                break
        set_users(users)
        return True
    return False

# ------------------- DATA MODELS -------------------
class Location:
    def __init__(self, name, lat, lon):
        self.name = name
        self.lat = lat
        self.lon = lon

class Contact:
    def __init__(self, name, chat_id, priority):
        self.name = name
        self.chat_id = chat_id
        self.priority = priority

# ------------------- SYSTEM -------------------
class PanicSystem:
    def __init__(self):
        self.locations, self.contacts = [], []
        self.load_data()

    def load_data(self):
        if os.path.exists(LOCATIONS_FILE):
            try:
                with open(LOCATIONS_FILE, 'r', encoding="utf-8") as f:
                    self.locations = [Location(**l) for l in json.load(f)]
            except json.JSONDecodeError:
                self.locations = []
        if os.path.exists(CONTACTS_FILE):
            try:
                with open(CONTACTS_FILE, 'r', encoding="utf-8") as f:
                    self.contacts = [Contact(**c) for c in json.load(f)]
            except json.JSONDecodeError:
                self.contacts = []

    def save_data(self):
        with open(LOCATIONS_FILE, 'w', encoding="utf-8") as f:
            json.dump([vars(l) for l in self.locations], f, indent=2)
        with open(CONTACTS_FILE, 'w', encoding="utf-8") as f:
            json.dump([vars(c) for c in self.contacts], f, indent=2)

    def save_alert(self, alert):
        alerts = load_json(ALERTS_FILE, [])
        alerts.append(alert)
        save_json(ALERTS_FILE, alerts)

    def add_contact(self, name, chat_id, priority):
        self.contacts.append(Contact(name, chat_id, priority))
        self.contacts.sort(key=lambda x: x.priority, reverse=True)
        self.save_data()

    def delete_contact(self, idx):
        if 0 <= idx < len(self.contacts):
            self.contacts.pop(idx)
            self.save_data()

    def add_location(self, name, lat, lon):
        self.locations.append(Location(name, lat, lon))
        self.save_data()

    def delete_location(self, idx):
        if 0 <= idx < len(self.locations):
            self.locations.pop(idx)
            self.save_data()

    def trigger_panic(self, idx):
        if 0 <= idx < len(self.locations):
            loc = self.locations[idx]
            time_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            link = f"https://www.google.com/maps/search/?api=1&query={loc.lat},{loc.lon}"
            message = f"🚨 *PANIC ALERT* 🚨\n\nTime: {time_str}\nLocation: *{loc.name}*\nMap: {link}"
            threading.Thread(target=self._send_messages, args=(message,), daemon=True).start()
            alert = {"time": time_str, "location": loc.name, "lat": loc.lat, "lon": loc.lon}
            self.save_alert(alert)
            return message
        return None

    def _send_messages(self, message):
        for c in self.contacts:
            self.send_telegram_message(c.chat_id, message)

    def send_telegram_message(self, chat_id, message):
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        try:
            requests.get(url, params={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}, timeout=5)
        except Exception as e:
            # GUI error only if a root exists; otherwise print
            try:
                messagebox.showerror("Telegram Error", f"Failed to send message to {chat_id}:\n{e}")
            except:
                print(f"Telegram Error: {e}")

# ------------------- NEW DATA ENTRY DIALOG -------------------
class DataEntryDialog(tk.Toplevel):
    """A professional, reusable modal dialog for adding or editing data."""
    def __init__(self, parent, title, fields, initial_data=None):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.parent = parent
        self.title(title)
        self.config(bg=CARD, padx=20, pady=20)

        self.fields = fields
        self.entries = {}
        self.result = None

        form_frame = ttk.Frame(self, style="Card.TFrame")
        form_frame.pack(fill="both", expand=True)

        for i, (label, field_type) in enumerate(fields):
            lbl = ttk.Label(form_frame, text=f"{label}:", style="Card.TLabel")
            lbl.grid(row=i, column=0, sticky="w", padx=10, pady=10)

            if field_type == "password":
                entry = ttk.Entry(form_frame, width=40, font=("Segoe UI", 10), show="*")
            elif field_type == "role":
                entry = ttk.Combobox(form_frame, values=[ROLE_ADMIN, ROLE_OPERATOR], state="readonly", width=37)
            else:
                entry = ttk.Entry(form_frame, width=40, font=("Segoe UI", 10))

            entry.grid(row=i, column=1, sticky="w", padx=10, pady=10)

            if initial_data and label in initial_data:
                if isinstance(entry, ttk.Combobox):
                    entry.set(initial_data.get(label, ""))
                else:
                    entry.insert(0, initial_data.get(label, ""))

            self.entries[label] = (entry, field_type)

        btn_frame = ttk.Frame(self, style="TFrame")
        btn_frame.pack(fill="x", pady=(20, 0))

        ok_btn = ttk.Button(btn_frame, text="Save", command=self.on_ok, style="Add.TButton")
        ok_btn.pack(side="right", padx=5)

        cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.destroy, style="Delete.TButton")
        cancel_btn.pack(side="right", padx=5)

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def on_ok(self):
        self.result = {}
        try:
            for label, (entry, field_type) in self.entries.items():
                value_str = entry.get().strip() if not isinstance(entry, ttk.Combobox) else entry.get().strip()
                if not value_str:
                    raise ValueError(f"'{label}' cannot be empty.")
                if field_type in ("text", "password", "role"):
                    self.result[label] = value_str
                elif field_type == "int":
                    self.result[label] = int(value_str)
                elif field_type == "float":
                    self.result[label] = float(value_str)
            self.destroy()
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e), parent=self)
            self.result = None

# ------------------- LOGIN / REGISTER WINDOWS -------------------
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("User Login")
        self.root.geometry("420x360")
        self.root.configure(bg=BG)

        self.setup_styles()

        card = ttk.Frame(root, style="Card.TFrame", padding=20)
        card.pack(expand=True, fill="both", padx=20, pady=20)

        ttk.Label(card, text="🔐 Panic System Login", style="Card.Header.TLabel").pack(pady=(0, 10))
        ttk.Label(card, text="Secure access • Role based", style="Card.Sub.TLabel").pack(pady=(0, 10))

        ttk.Label(card, text="Username:", style="Card.TLabel").pack(pady=(10, 0))
        self.username_entry = ttk.Entry(card, width=34)
        self.username_entry.pack()

        ttk.Label(card, text="Password:", style="Card.TLabel").pack(pady=(10, 0))
        self.password_entry = ttk.Entry(card, width=34, show="*")
        self.password_entry.pack()

        self.remember_var = tk.BooleanVar(value=True)
        remember = ttk.Checkbutton(card, text="Remember me on this device", variable=self.remember_var)
        remember.pack(pady=(8, 0))

        btns = ttk.Frame(card)
        btns.pack(pady=16)
        ttk.Button(btns, text="Login", style="Add.TButton", command=self.login).pack(side="left", padx=6)
        ttk.Button(btns, text="Register", style="Edit.TButton", command=self.register).pack(side="left", padx=6)

        # Auto-login from session if valid
        self.try_autologin()

        self.root.bind("<Return>", lambda e: self.login())

    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        style.configure('.', font=("Segoe UI", 10), background=BG, foreground=TEXT)
        style.configure('TFrame', background=BG)
        style.configure('TLabel', background=BG, foreground=TEXT)
        style.configure('Card.TFrame', background=CARD, relief='solid', borderwidth=1)
        style.configure('Card.Header.TLabel', font=('Segoe UI', 16, 'bold'), background=CARD, foreground=TEXT)
        style.configure('Card.Sub.TLabel', font=('Segoe UI', 11), background=CARD, foreground=SUBTEXT)
        style.configure('Card.TLabel', background=CARD, foreground=TEXT)
        style.configure('Add.TButton', font=('Segoe UI', 10, 'bold'), padding=(10, 8), background=SUCCESS, foreground='white')
        style.map('Add.TButton', background=[('active', '#218838')])
        style.configure('Edit.TButton', font=('Segoe UI', 10, 'bold'), padding=(10, 8), background=PRIMARY, foreground='white')
        style.map('Edit.TButton', background=[('active', '#0069D9')])
        style.configure('Delete.TButton', font=('Segoe UI', 10, 'bold'), padding=(10, 8), background=DANGER, foreground='white')
        style.map('Delete.TButton', background=[('active', '#C82333')])

    def try_autologin(self):
        session = get_session()
        if session.get("remember") and session.get("username"):
            u = find_user(session["username"])
            if u is not None:
                self.root.after(100, lambda: self.launch_app(u))

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        u = find_user(username)
        if not u:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            return

        if verify_password(u, password):
            # migrate if legacy
            migrate_legacy_password(u, password)
            if self.remember_var.get():
                set_session({"username": username, "remember": True})
            else:
                clear_session()
            self.launch_app(u)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def register(self):
        users = get_users()
        first_user = (len(users) == 0)

        # Registration dialog
        fields = [("Username", "text"), ("Password", "password")]
        if first_user:
            fields.append(("Role", "role"))  # First user can pick Admin/Operator
        dialog = DataEntryDialog(self.root, "Register New User", fields)
        result = dialog.result
        if not result:
            return

        username = result["Username"].strip()
        password = result["Password"].strip()
        role = result.get("Role", ROLE_OPERATOR if not first_user else ROLE_ADMIN)

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty.")
            return
        if find_user(username):
            messagebox.showerror("Error", "Username already exists.")
            return

        salt = make_salt()
        new_user = {
            "username": username,
            "role": role,
            "salt": salt,
            "password_hash": hash_password(password, salt)
        }
        users.append(new_user)
        set_users(users)
        messagebox.showinfo("Success", f"User '{username}' registered as {role}. You can now log in.")

    def launch_app(self, user_obj):
        try:
            messagebox.showinfo("Login Successful", f"Welcome, {user_obj['username']} ({user_obj['role']})!")
        except:
            pass
        self.root.destroy()
        main_app(user_obj)

# ------------------- GUI -------------------
class PanicGUI:
    def __init__(self, root, system: PanicSystem, current_user: dict):
        self.system = system
        self.user = current_user
        self.root = root
        root.title(f"🚨 Panic Alert System — {self.user['username']} ({self.user['role']})")
        root.geometry("1100x650")
        root.config(bg=BG)
        root.minsize(900, 600)

        self.is_admin = (self.user.get("role") == ROLE_ADMIN)

        # --- Setup Styles ---
        self.setup_styles()

        # --- Top Header ---
        header = tk.Frame(root, bg=HEADER_BG)
        header.pack(fill="x")
        title = tk.Label(header, text="🚨 Panic Alert Control Dashboard", bg=HEADER_BG, fg="white",
                         font=("Segoe UI", 20, "bold"), pady=10)
        title.pack(side="left", padx=10)

        # User badge
        user_badge = tk.Label(header, text=f"{self.user['username']} • {self.user['role']}",
                              bg=HEADER_BG, fg="#CED4DA", font=("Segoe UI", 11, "bold"))
        user_badge.pack(side="right", padx=10)

        # Menu
        menubar = tk.Menu(root)
        account = tk.Menu(menubar, tearoff=0)
        account.add_command(label="Profile", command=self.show_profile)
        account.add_separator()
        account.add_command(label="Logout", command=self.logout)
        menubar.add_cascade(label="Account", menu=account)
        root.config(menu=menubar)

        # --- Main Content Frame ---
        main_frame = ttk.Frame(root, padding=15)
        main_frame.pack(expand=True, fill="both")

        self.tab_control = ttk.Notebook(main_frame)
        self.tab_control.pack(expand=True, fill="both")

        self.tabs = {
            "📍 Locations": ttk.Frame(self.tab_control, style="TFrame", padding=10),
            "👥 Contacts": ttk.Frame(self.tab_control, style="TFrame", padding=10),
            "📜 Alerts": ttk.Frame(self.tab_control, style="TFrame", padding=10)
        }
        for name, frame in self.tabs.items():
            self.tab_control.add(frame, text=name)

        self.selected_location = None
        self.selected_contact = None
        self.panic_button = None

        self.create_locations_tab()
        self.create_contacts_tab()
        self.create_alerts_tab()

        # Role enforcement (disable CRUD for operators)
        if not self.is_admin:
            self.disable_operator_restricted()

    # ------------------- Styles -------------------
    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except:
            pass
        style.configure('.', font=("Segoe UI", 10), background=BG, foreground=TEXT)
        style.configure('TFrame', background=BG)
        style.configure('TLabel', background=BG, foreground=TEXT)

        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab',
                        font=('Segoe UI', 14, 'bold'),
                        padding=[20, 10],
                        background=BG,
                        foreground=SUBTEXT,
                        borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', BG)],
                  foreground=[('selected', PRIMARY)])

        style.configure('Card.TFrame', background=CARD, relief='solid', borderwidth=1)
        style.configure('Selected.Card.TFrame', background="#E7F1FF", relief='solid', borderwidth=2)
        style.configure('Card.TLabel', background=CARD, foreground=TEXT)
        style.configure('Card.Header.TLabel', font=('Segoe UI', 16, 'bold'), background=CARD, foreground=TEXT)
        style.configure('Card.Sub.TLabel', font=('Segoe UI', 12), background=CARD, foreground=SUBTEXT)
        style.configure('Card.Icon.TLabel', font=("Segoe UI Emoji", 28), background=CARD)

        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=(10, 8), borderwidth=0)
        style.map('TButton',
                  background=[('active', '#E2E6EA')],
                  foreground=[('active', TEXT)])

        style.configure('Add.TButton', background=SUCCESS, foreground='white')
        style.map('Add.TButton', background=[('active', '#218838')])

        style.configure('Edit.TButton', background=PRIMARY, foreground='white')
        style.map('Edit.TButton', background=[('active', '#0069D9')])

        style.configure('Delete.TButton', background=DANGER, foreground='white')
        style.map('Delete.TButton', background=[('active', '#C82333')])

        style.configure('Panic.TButton',
                        font=('Segoe UI', 22, 'bold'),
                        padding=(20, 30),
                        background=PANIC,
                        foreground='white')
        style.map('Panic.TButton',
                  background=[('active', '#D9042D'), ('disabled', '#FFAAB8')])

    # ------------------- Layout Utilities -------------------
    def create_scrollable_area(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=BG, highlightthickness=0)
        scroll_y = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style="TFrame")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll_y.set)

        canvas.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")
        return scrollable_frame

    def create_card(self, parent, title, subtitle, icon_text, click_command, selected=False):
        style = "Selected.Card.TFrame" if selected else "Card.TFrame"
        card = ttk.Frame(parent, style=style, cursor="hand2")
        card.pack(padx=10, pady=8, fill="x")

        icon = ttk.Label(card, text=icon_text, style="Card.Icon.TLabel")
        icon.grid(row=0, column=0, rowspan=2, padx=(20, 15), pady=15)

        lbl_title = ttk.Label(card, text=title, style="Card.Header.TLabel")
        lbl_title.grid(row=0, column=1, sticky="w", pady=(10, 0))

        lbl_subtitle = ttk.Label(card, text=subtitle, style="Card.Sub.TLabel")
        lbl_subtitle.grid(row=1, column=1, sticky="w", pady=(0, 10))

        for widget in (card, icon, lbl_title, lbl_subtitle):
            widget.bind("<Button-1>", lambda e: click_command())
        return card

    # ------------------- Tabs -------------------
    def create_locations_tab(self):
        frame = self.tabs["📍 Locations"]

        main_area = ttk.Frame(frame)
        main_area.pack(side="left", fill="both", expand=True)

        panic_area = ttk.Frame(frame, padding=(20, 0))
        panic_area.pack(side="right", fill="y")

        # --- Main Area ---
        button_bar = ttk.Frame(main_area)
        button_bar.pack(fill="x", pady=(0, 10))

        self.btn_add_loc = ttk.Button(button_bar, text="➕ Add Location", style="Add.TButton", command=self.add_location)
        self.btn_edit_loc = ttk.Button(button_bar, text="✏️ Edit Selected", style="Edit.TButton", command=self.edit_location)
        self.btn_del_loc = ttk.Button(button_bar, text="🗑 Delete Selected", style="Delete.TButton", command=self.delete_location)

        self.btn_add_loc.pack(side="left", padx=5)
        self.btn_edit_loc.pack(side="left", padx=5)
        self.btn_del_loc.pack(side="left", padx=5)

        ttk.Separator(main_area, orient="horizontal").pack(fill="x", pady=5)

        self.loc_canvas = self.create_scrollable_area(main_area)
        self.update_locations()

        # --- Panic Area ---
        ttk.Label(panic_area, text="TRIGGER ALERT", font=("Segoe UI", 16, "bold"), foreground=PANIC).pack(pady=10)
        self.panic_button = ttk.Button(panic_area, text="🚨\nPANIC",
                                       style="Panic.TButton",
                                       command=self.trigger_panic,
                                       state="disabled")
        self.panic_button.pack(expand=True, anchor="center")

    def create_contacts_tab(self):
        frame = self.tabs["👥 Contacts"]

        button_bar = ttk.Frame(frame)
        button_bar.pack(fill="x", pady=(0, 10))

        self.btn_add_cont = ttk.Button(button_bar, text="➕ Add Contact", style="Add.TButton", command=self.add_contact)
        self.btn_edit_cont = ttk.Button(button_bar, text="✏️ Edit Selected", style="Edit.TButton", command=self.edit_contact)
        self.btn_del_cont = ttk.Button(button_bar, text="🗑 Delete Selected", style="Delete.TButton", command=self.delete_contact)

        self.btn_add_cont.pack(side="left", padx=5)
        self.btn_edit_cont.pack(side="left", padx=5)
        self.btn_del_cont.pack(side="left", padx=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=5)

        self.cont_canvas = self.create_scrollable_area(frame)
        self.update_contacts()

    def create_alerts_tab(self):
        frame = self.tabs["📜 Alerts"]

        button_bar = ttk.Frame(frame)
        button_bar.pack(fill="x", pady=(0, 10))
        ttk.Button(button_bar, text="🔄 Refresh Alerts", style="Edit.TButton", command=self.update_alerts).pack(side="left", padx=5)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=5)

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.alert_text = tk.Text(text_frame, font=("Consolas", 11), bg=CARD, fg=TEXT,
                                  wrap="word", relief="solid", borderwidth=1, highlightcolor=BORDER)

        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.alert_text.yview)
        self.alert_text['yscrollcommand'] = scrollbar.set

        scrollbar.pack(side="right", fill="y")
        self.alert_text.pack(fill="both", expand=True)

        self.update_alerts()

    # ------------------- Data Updates -------------------
    def update_locations(self):
        if not hasattr(self, 'loc_canvas'): return
        for w in self.loc_canvas.winfo_children():
            w.destroy()

        if not self.system.locations:
            ttk.Label(self.loc_canvas, text="No locations added yet.\nClick 'Add Location' to start.",
                      font=("Segoe UI", 12, "italic"),
                      style="Card.Sub.TLabel", background=BG).pack(pady=30)

        for i, l in enumerate(self.system.locations):
            self.create_card(self.loc_canvas, l.name,
                             f"Latitude: {l.lat} | Longitude: {l.lon}",
                             "📍",
                             click_command=lambda idx=i: self.select_location(idx),
                             selected=(i == self.selected_location))

        if self.panic_button:
            state = "normal" if self.selected_location is not None else "disabled"
            self.panic_button.config(state=state)

    def update_contacts(self):
        if not hasattr(self, 'cont_canvas'): return
        for w in self.cont_canvas.winfo_children():
            w.destroy()

        if not self.system.contacts:
            ttk.Label(self.cont_canvas, text="No contacts added yet.\nClick 'Add Contact' to start.",
                      font=("Segoe UI", 12, "italic"),
                      style="Card.Sub.TLabel", background=BG).pack(pady=30)

        for i, c in enumerate(self.system.contacts):
            self.create_card(self.cont_canvas, c.name,
                             f"Chat ID: {c.chat_id} | Priority: {c.priority}",
                             "👥",
                             click_command=lambda idx=i: self.select_contact(idx),
                             selected=(i == self.selected_contact))

    def update_alerts(self):
        if not hasattr(self, 'alert_text'): return
        self.alert_text.config(state="normal")
        self.alert_text.delete("1.0", tk.END)

        alerts = load_json(ALERTS_FILE, [])

        if not alerts:
            self.alert_text.insert(tk.END, "No alerts have been sent yet.")
        else:
            for a in reversed(alerts):
                link = f"https://www.google.com/maps/search/?api=1&query={a['lat']},{a['lon']}"
                self.alert_text.insert(tk.END, f"Time:     {a['time']}\nLocation: {a['location']}\nMap Link: {link}\n\n")

        self.alert_text.config(state="disabled")

    # ------------------- CRUD -------------------
    def add_location(self):
        if not self.check_admin():
            return
        fields = [("Name", "text"), ("Latitude", "float"), ("Longitude", "float")]
        dialog = DataEntryDialog(self.root, "Add New Location", fields)
        result = dialog.result

        if result:
            self.system.add_location(result["Name"], result["Latitude"], result["Longitude"])
            self.update_locations()

    def edit_location(self):
        if not self.check_admin():
            return
        if self.selected_location is None:
            messagebox.showwarning("Select", "Please select a location to edit.", parent=self.root)
            return

        loc = self.system.locations[self.selected_location]
        fields = [("Name", "text"), ("Latitude", "float"), ("Longitude", "float")]
        initial_data = {"Name": loc.name, "Latitude": loc.lat, "Longitude": loc.lon}
        dialog = DataEntryDialog(self.root, "Edit Location", fields, initial_data)
        result = dialog.result

        if result:
            loc.name, loc.lat, loc.lon = result["Name"], result["Latitude"], result["Longitude"]
            self.system.save_data()
            self.update_locations()

    def delete_location(self):
        if not self.check_admin():
            return
        if self.selected_location is None:
            messagebox.showwarning("Select", "Please select a location to delete.", parent=self.root)
            return

        loc_name = self.system.locations[self.selected_location].name
        if messagebox.askyesno("Confirm Delete", f"Delete '{loc_name}'?", parent=self.root):
            self.system.delete_location(self.selected_location)
            self.selected_location = None
            self.update_locations()

    def add_contact(self):
        if not self.check_admin():
            return
        fields = [("Name", "text"), ("Chat ID", "text"), ("Priority (1-5)", "int")]
        dialog = DataEntryDialog(self.root, "Add New Contact", fields)
        result = dialog.result

        if result:
            self.system.add_contact(result["Name"], result["Chat ID"], result["Priority (1-5)"])
            self.update_contacts()

    def edit_contact(self):
        if not self.check_admin():
            return
        if self.selected_contact is None:
            messagebox.showwarning("Select", "Please select a contact to edit.", parent=self.root)
            return

        c = self.system.contacts[self.selected_contact]
        fields = [("Name", "text"), ("Chat ID", "text"), ("Priority (1-5)", "int")]
        initial_data = {"Name": c.name, "Chat ID": c.chat_id, "Priority (1-5)": c.priority}
        dialog = DataEntryDialog(self.root, "Edit Contact", fields, initial_data)
        result = dialog.result

        if result:
            c.name, c.chat_id, c.priority = result["Name"], result["Chat ID"], result["Priority (1-5)"]
            self.system.contacts.sort(key=lambda x: x.priority, reverse=True)
            self.system.save_data()
            self.update_contacts()

    def delete_contact(self):
        if not self.check_admin():
            return
        if self.selected_contact is None:
            messagebox.showwarning("Select", "Please select a contact to delete.", parent=self.root)
            return

        contact_name = self.system.contacts[self.selected_contact].name
        if messagebox.askyesno("Confirm Delete", f"Delete '{contact_name}'?", parent=self.root):
            self.system.delete_contact(self.selected_contact)
            self.selected_contact = None
            self.update_contacts()

    def trigger_panic(self):
        if self.selected_location is None:
            messagebox.showwarning("Select", "Please select a location to trigger panic.", parent=self.root)
            return

        loc_name = self.system.locations[self.selected_location].name
        if not messagebox.askyesno("CONFIRM PANIC",
                                   f"🚨 Send panic alert for\n\n>> {loc_name} <<\n\nThis notifies all contacts immediately.",
                                   parent=self.root, icon='warning'):
            return

        msg = self.system.trigger_panic(self.selected_location)
        if msg:
            messagebox.showinfo("Panic Alert Sent", f"Successfully sent panic alert for '{loc_name}'.", parent=self.root)
            self.update_alerts()
            self.tab_control.select(self.tabs["📜 Alerts"])

    # ------------------- Selections -------------------
    def select_location(self, idx):
        self.selected_location = idx
        self.update_locations()

    def select_contact(self, idx):
        self.selected_contact = idx
        self.update_contacts()

    # ------------------- Role / Account -------------------
    def check_admin(self):
        if not self.is_admin:
            messagebox.showinfo("Restricted", "Only Admins can modify data. Switch to an Admin account.")
            return False
        return True

    def disable_operator_restricted(self):
        # Disable CRUD for Operators with soft hint
        for btn in (self.btn_add_loc, self.btn_edit_loc, self.btn_del_loc,
                    self.btn_add_cont, self.btn_edit_cont, self.btn_del_cont):
            btn.state(["disabled"])
            btn_tip = tk.Label(btn, text="Admin only", bg=BG, fg=SUBTEXT, font=("Segoe UI", 8))
            # optional: skip placing small hints to avoid layout noise

    def show_profile(self):
        u = self.user
        info = f"Username: {u.get('username')}\nRole: {u.get('role')}\n\nData files:\n- {USERS_FILE}\n- {SESSION_FILE}\n- {LOCATIONS_FILE}\n- {CONTACTS_FILE}\n- {ALERTS_FILE}"
        messagebox.showinfo("Profile", info, parent=self.root)

    def logout(self):
        if messagebox.askyesno("Logout", "Do you want to logout?", parent=self.root):
            clear_session()
            self.root.destroy()
            relaunch_login()

# ------------------- APP ENTRY -------------------
def main_app(user_obj):
    system = PanicSystem()
    root = tk.Tk()
    gui = PanicGUI(root, system, current_user=user_obj)
    root.mainloop()

def relaunch_login():
    login_root = tk.Tk()
    LoginWindow(login_root)
    login_root.mainloop()

if __name__ == "__main__":
    # If a valid session exists, LoginWindow will auto-launch the main app
    relaunch_login()
