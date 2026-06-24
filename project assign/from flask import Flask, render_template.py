from flask import Flask, render_template_string, request, session, redirect, url_for, flash, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
import io
import csv
import time

try:
    import openpyxl
except ImportError:
    openpyxl = None

def ensure_openpyxl(auto_install=True):
    """
    Ensure openpyxl is importable. If missing and auto_install is True,
    attempt to install it via pip at runtime. Returns True if available.
    """
    global openpyxl
    if openpyxl is not None:
        return True
    if not auto_install:
        return False
    try:
        import sys, subprocess, importlib
        subprocess.check_call([sys.executable, "-m", "pip", "install", "openpyxl"])
        openpyxl = importlib.import_module("openpyxl")
        print("openpyxl installed and loaded.")
        return True
    except Exception as e:
        print("Unable to install/load openpyxl:", e)
        openpyxl = None
        return False

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-secret"
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["DATABASE"] = "app.db"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "zip"}
MAX_USERS = 200
MAX_STUDENTS = 150
MAX_TEACHERS = 50


def get_db():
    if "db" not in g:
        # increase timeout and allow cross-thread usage to reduce "database is locked" errors
        conn = sqlite3.connect(app.config["DATABASE"], timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # improve concurrency
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass
        g.db = conn
    return g.db


def executescript_with_retry(db, script, retries=5, backoff=0.2):
    for i in range(retries):
        try:
            db.executescript(script)
            return
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and i < retries - 1:
                time.sleep(backoff * (2 ** i))
                continue
            raise

def db_execute(db, sql, params=(), commit=False, retries=5, backoff=0.2):
    for i in range(retries):
        try:
            cur = db.execute(sql, params)
            if commit:
                db.commit()
            return cur
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and i < retries - 1:
                time.sleep(backoff * (2 ** i))
                continue
            raise

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_user_counts(db):
    counts = {"total": 0, "student": 0, "teacher": 0, "admin": 0}
    rows = db.execute("SELECT role, COUNT(*) AS cnt FROM users GROUP BY role").fetchall()
    for row in rows:
        counts[row["role"]] = row["cnt"]
    counts["total"] = counts["student"] + counts["teacher"] + counts["admin"]
    return counts


def init_db():
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    db = get_db()
    # use executescript_with_retry for initial schema setup
    executescript_with_retry(
        db,
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','teacher','admin')),
            password_changed INTEGER NOT NULL DEFAULT 0,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            department TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            due_date TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            grade TEXT,
            feedback TEXT,
            FOREIGN KEY(assignment_id) REFERENCES assignments(id),
            FOREIGN KEY(student_id) REFERENCES users(id)
        );
        """
    )
    existing_columns = [row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()]
    if "password_changed" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN password_changed INTEGER NOT NULL DEFAULT 0", commit=True)
    if "full_name" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN full_name TEXT", commit=True)
    if "email" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN email TEXT", commit=True)
    if "phone" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN phone TEXT", commit=True)
    if "department" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN department TEXT", commit=True)
    if "created_at" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN created_at TEXT", commit=True)
    if "updated_at" not in existing_columns:
        db_execute(db, "ALTER TABLE users ADD COLUMN updated_at TEXT", commit=True)
    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if not admin:
        db_execute(
            db,
            "INSERT INTO users(username, password, role, password_changed, full_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
            ("admin", generate_password_hash("admin123"), "admin", 1, "Administrator"),
            commit=True,
        )
    db_execute(db, "UPDATE users SET password_changed = 1 WHERE role = 'admin'", commit=True)
    db.commit()


def login_required(roles=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                flash("Access denied.")
                return redirect(url_for("dashboard"))
            if session.get("role") in ("student", "teacher") and not session.get("password_changed") and request.endpoint != "change_password":
                return redirect(url_for("change_password"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


ALLOWED_USER_UPLOAD_EXTENSIONS = {"xlsx", "csv"}


def allowed_user_upload(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_USER_UPLOAD_EXTENSIONS


def render_template_with_watermark(template, **context):
        watermark_css = """
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
                <style>
                        :root{
                        --bg-1: #f7fbff;
                        --bg-2: #eff7ff;
                        --surface: rgba(255,255,255,0.95);
                        --surface-strong: rgba(255,255,255,0.98);
                        --card: rgba(255,255,255,0.92);
                        --primary: #2563eb;
                        --accent: #0891b2;
                        --accent-dark: #0f172a;
                        --text: #0f172a;
                        --muted: #475569;
                        --border: rgba(15,23,42,0.08);
                        --shadow: 0 24px 80px rgba(15,23,42,0.08);
                }
                html,body{height:100%;}
                body{
                        margin:0; font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial;
                        background: radial-gradient(circle at top left, rgba(37,99,235,0.16), transparent 20%),
                                    radial-gradient(circle at bottom right, rgba(2,132,199,0.12), transparent 20%),
                                    linear-gradient(180deg, var(--bg-1), var(--bg-2));
                        color: var(--text);
                        -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
                }
                body * { color: inherit; }
                .app-shell{ display: flex; min-height:100vh; gap: 20px; padding: 24px; }
                .sidebar{ width: 260px; padding: 28px 20px; background: var(--surface); border: 1px solid var(--border); box-shadow: var(--shadow); border-radius: 24px; position: sticky; top: 20px; align-self: flex-start; }
                .sidebar h2{ font-size: 1.25rem; margin-bottom: 1.5rem; color: var(--accent-dark); }
                .nav-menu{ list-style:none; padding:0; margin:0; display:grid; gap:10px; }
                .nav-menu li a{ display:flex; align-items:center; justify-content:space-between; padding:12px 14px; border-radius: 16px; background: rgba(15,23,42,0.04); color: var(--accent-dark); text-decoration:none; font-weight:600; transition: background .25s ease, transform .25s ease; }
                .nav-menu li a:hover{ background: rgba(37,99,235,0.12); transform: translateX(4px); }
                .nav-menu li a.active{ background: linear-gradient(135deg, var(--primary), var(--accent)); color: #fff; }
                .main-content{ flex:1; display:flex; flex-direction:column; gap:24px; }
                .topbar{ display:flex; align-items:center; justify-content:space-between; gap:16px; padding:18px 24px; border-radius:24px; background: var(--surface); border:1px solid var(--border); box-shadow: var(--shadow); }
                .topbar .search-box{ flex:1; display:flex; align-items:center; gap:12px; background: rgba(15,23,42,0.03); padding: 10px 14px; border-radius: 18px; }
                .topbar .search-box input{ width:100%; border:none; background:transparent; color: var(--text); outline:none; }
                .topbar .user-summary{ display:flex; align-items:center; gap:12px; }
                .topbar .user-summary .avatar{ width:44px; height:44px; border-radius:50%; background: linear-gradient(135deg, var(--primary), var(--accent)); display:flex; align-items:center; justify-content:center; color:#fff; font-weight:700; }
                .stats-grid{ display:grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap:18px; }
                .stat-card{ background: var(--surface); border:1px solid var(--border); border-radius:24px; padding:24px; box-shadow: var(--shadow); transition: transform .2s ease; }
                .stat-card:hover{ transform: translateY(-4px); }
                .stat-card h3{ margin:0 0 8px; font-size: 1rem; color: var(--muted); }
                .stat-card .value{ font-size:2rem; font-weight:700; color: var(--accent-dark); }
                .content-panel{ display:grid; grid-template-columns: 1.25fr 0.75fr; gap:22px; }
                .panel-card{ background: var(--surface); border:1px solid var(--border); border-radius:24px; box-shadow: var(--shadow); padding:24px; }
                .panel-card h3{ margin-top:0; color: var(--accent-dark); }
                .panel-card p{ color: var(--muted); }
                .panel-card .profile-detail{ display:grid; grid-template-columns: auto 1fr; gap: 14px 18px; margin-top:16px; }
                .panel-card .profile-detail strong{ display:block; color: var(--muted); font-size:0.95rem; }
                .panel-card .profile-detail span{ color: var(--text); font-size:1rem; }
                .btn-pill{ border-radius:999px; padding: 10px 18px; }
                .watermark { position: fixed; left: 0; bottom: 0; width: 100%; text-align: center; font-size: 0.85rem; color: rgba(15,23,42,0.18); pointer-events: none; z-index: 9999; }
                .bg-graphic{ position: fixed; inset: 0; pointer-events: none; z-index: 0; opacity: 0.3; }
                .content-root{ position: relative; z-index: 5; }
                @media (max-width:1100px){ .content-panel{ grid-template-columns: 1fr; } }
                @media (max-width:900px){ .app-shell{ flex-direction:column; } .sidebar{ position:relative; width:100%; top:0; } }
                @media (max-width:768px){ .card-header h2{ font-size:1.05rem; } }
                </style>
        """

        # soft SVG shapes inserted before body close so they sit behind content
        svg_background = '''
        <div class="bg-graphic" aria-hidden="true">
            <svg viewBox="0 0 1200 800" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="g1" x1="0" x2="1">
                        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.35"/>
                        <stop offset="100%" stop-color="#06b6d4" stop-opacity="0.3"/>
                    </linearGradient>
                    <linearGradient id="g2" x1="0" x2="1">
                        <stop offset="0%" stop-color="#ffffff" stop-opacity="0.28"/>
                        <stop offset="100%" stop-color="#93c5fd" stop-opacity="0.08"/>
                    </linearGradient>
                    <filter id="blur"><feGaussianBlur stdDeviation="80"/></filter>
                </defs>
                <g filter="url(#blur)">
                    <circle cx="220" cy="220" r="260" fill="url(#g1)"/>
                    <ellipse cx="910" cy="620" rx="360" ry="220" fill="url(#g2)"/>
                    <ellipse cx="520" cy="120" rx="180" ry="100" fill="#ffffff" fill-opacity="0.16"/>
                </g>
            </svg>
        </div>
        '''

        template = template.replace("</head>", watermark_css + "</head>")
        template = template.replace("</body>", svg_background + '<div class="watermark">Teetech Limited</div></body>')
        # ensure main content stacks above graphics
        template = template.replace('<div class="container">', '<div class="container content-root">')
        return render_template_string(template, **context)


def parse_user_upload(file, ext):
    file.stream.seek(0)
    if ext == "csv":
        text_stream = io.TextIOWrapper(file.stream, encoding="utf-8", errors="replace")
        rows = list(csv.reader(text_stream))
        if not rows:
            return []
        headers = [str(h).strip().lower() for h in rows[0]]
        items = []
        if "username" in headers and "role" in headers:
            username_index = headers.index("username")
            role_index = headers.index("role")

            def find_header_index(candidates):
                for c in candidates:
                    for i, h in enumerate(headers):
                        if h == c or h.replace(" ", "") == c.replace(" ", ""):
                            return i
                return None

            fullname_index = find_header_index(["full name", "fullname"])
            email_index = find_header_index(["school email address", "personal email address", "email address", "emailaddress", "email"]) 
            department_index = find_header_index(["department"]) 
            phone_index = find_header_index(["phone number", "phone", "mobile", "mobile number", "telephone", "telephone number", "contact number", "personal phone"]) 

            def _normalize_phone(v):
                if v is None:
                    return None
                s = str(v).strip()
                # remove common leading apostrophe/quote and zero-width chars
                s = s.lstrip("'\"\u200B\uFEFF\u00A0")
                # Excel may export numeric text with ".0" suffix - remove if numeric
                if s.endswith('.0') and s[:-2].replace('+', '').isdigit():
                    s = s[:-2]
                return s if s else None

            for row in rows[1:]:
                if len(row) > max(username_index, role_index):
                    item = {"username": str(row[username_index]).strip(), "role": str(row[role_index]).strip().lower()}
                    if fullname_index is not None and len(row) > fullname_index:
                        val = row[fullname_index]
                        if val is not None:
                            item["full_name"] = str(val).strip()
                    if email_index is not None and len(row) > email_index:
                        val = row[email_index]
                        if val is not None:
                            item["email"] = str(val).strip()
                    if department_index is not None and len(row) > department_index:
                        val = row[department_index]
                        if val is not None:
                            item["department"] = str(val).strip()
                    if phone_index is not None and len(row) > phone_index:
                        val = row[phone_index]
                        if val is not None:
                            item["phone"] = _normalize_phone(val)
                    items.append(item)
        else:
            for row in rows:
                if len(row) >= 2:
                    items.append({"username": str(row[0]).strip(), "role": str(row[1]).strip().lower()})
        return items
    if ext == "xlsx":
        if not ensure_openpyxl():
            raise RuntimeError("openpyxl is required for .xlsx imports. Please install it (pip install openpyxl).")
        workbook = openpyxl.load_workbook(file.stream, data_only=True)
        sheet = workbook.active
        rows = list(sheet.iter_rows(values_only=True))
        if not rows:
            return []
        headers = [str(cell).strip().lower() if cell is not None else "" for cell in rows[0]]
        items = []
        if "username" in headers and "role" in headers:
            username_index = headers.index("username")
            role_index = headers.index("role")

            def find_header_index(candidates):
                for c in candidates:
                    for i, h in enumerate(headers):
                        if h == c or h.replace(" ", "") == c.replace(" ", ""):
                            return i
                return None

            fullname_index = find_header_index(["full name", "fullname"])
            email_index = find_header_index(["school email address", "personal email address", "email address", "emailaddress", "email"]) 
            department_index = find_header_index(["department"]) 
            phone_index = find_header_index(["phone number", "phone", "mobile", "mobile number", "telephone", "telephone number", "contact number", "personal phone"]) 

            def _normalize_phone(v):
                if v is None:
                    return None
                s = str(v).strip()
                s = s.lstrip("'\"\u200B\uFEFF\u00A0")
                if s.endswith('.0') and s[:-2].replace('+', '').isdigit():
                    s = s[:-2]
                return s if s else None

            for row in rows[1:]:
                if row and len(row) > max(username_index, role_index):
                    item = {"username": str(row[username_index]).strip(), "role": str(row[role_index]).strip().lower()}
                    if fullname_index is not None and len(row) > fullname_index:
                        val = row[fullname_index]
                        if val is not None:
                            item["full_name"] = str(val).strip()
                    if email_index is not None and len(row) > email_index:
                        val = row[email_index]
                        if val is not None:
                            item["email"] = str(val).strip()
                    if department_index is not None and len(row) > department_index:
                        val = row[department_index]
                        if val is not None:
                            item["department"] = str(val).strip()
                    if phone_index is not None and len(row) > phone_index:
                        val = row[phone_index]
                        if val is not None:
                            item["phone"] = _normalize_phone(val)
                    items.append(item)
        else:
            for row in rows:
                if row and len(row) >= 2:
                    items.append({"username": str(row[0]).strip(), "role": str(row[1]).strip().lower()})
        return items
    return []


def validate_upload(file):
    if not file:
        return "No file part."
    if file.filename == "":
        return "No selected file."
    if not allowed_file(file.filename):
        return "File type not allowed. Allowed: %s" % ", ".join(sorted(ALLOWED_EXTENSIONS))
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size == 0:
        return "Uploaded file is empty."
    if size > app.config["MAX_CONTENT_LENGTH"]:
        return "File exceeds maximum allowed size."
    return None


@app.route("/uploads/<path:filename>")
@login_required()
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/preview/<int:submission_id>")
@login_required(["teacher", "admin"])
def preview(submission_id):
    db = get_db()
    submission = db.execute("SELECT filename FROM submissions WHERE id = ?", (submission_id,)).fetchone()
    if not submission:
        flash("Submission not found.")
        return redirect(url_for("submissions"))
    filename = submission["filename"]
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    if ext == "txt":
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            content = "Unable to load file content."
        return render_template_string(
            """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Preview Submission</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px; }
                    .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                    .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                    pre { white-space: pre-wrap; word-break: break-word; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="card">
                        <div class="card-header">
                            <h2 class="mb-0">Preview: {{ filename }}</h2>
                        </div>
                        <div class="card-body">
                            <pre>{{ content }}</pre>
                            <a href="{{ url_for('submissions') }}" class="btn btn-secondary w-100 mt-3">Back to Submissions</a>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """,
            filename=filename,
            content=content,
        )
    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Preview Submission</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .embed-responsive { width: 100%; height: 80vh; border: 1px solid #dee2e6; border-radius: 10px; overflow: hidden; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Preview: {{ filename }}</h2>
                    </div>
                    <div class="card-body">
                        <div class="embed-responsive">
                            <iframe src="{{ url_for('uploaded_file', filename=filename) }}" frameborder="0" width="100%" height="100%"></iframe>
                        </div>
                        <a href="{{ url_for('submissions') }}" class="btn btn-secondary w-100 mt-3">Back to Submissions</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        filename=filename,
    )


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
        else:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user["password"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["password_changed"] = user["password_changed"]
                if user["role"] in ("student", "teacher") and not user["password_changed"]:
                    return redirect(url_for("change_password"))
                return redirect(url_for("dashboard"))
            flash("Invalid credentials.")
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Assignment Portal</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; }
                .container { max-width: 400px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                button:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Assignment Portal</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-danger">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        <form method="post">
                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input class="form-control" name="username">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input class="form-control" name="password" type="password">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Login</button>
                        </form>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    )


@app.route("/change_password", methods=["GET", "POST"])
@login_required()
def change_password():
    if session.get("role") not in ("student", "teacher"):
        return redirect(url_for("dashboard"))
    db = get_db()
    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        if not new_password or not confirm_password:
            flash("Both password fields are required.")
        elif new_password != confirm_password:
            flash("Passwords do not match.")
        elif new_password == session["username"]:
            flash("New password must be different from your username.")
        else:
            db_execute(
                db,
                "UPDATE users SET password = ?, password_changed = 1 WHERE id = ?",
                (generate_password_hash(new_password), session["user_id"]),
                commit=True,
            )
            session["password_changed"] = 1
            flash("Password updated successfully. Please log in again.")
            session.clear()
            return redirect(url_for("login"))
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Change Password</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; }
                .container { max-width: 450px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Change Password</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-danger">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        <p>Please create a new password different from your username.</p>
                        <form method="post">
                            <div class="mb-3">
                                <label class="form-label">New Password</label>
                                <input class="form-control" type="password" name="new_password" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Confirm Password</label>
                                <input class="form-control" type="password" name="confirm_password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Save Password</button>
                        </form>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile")
@login_required()
def profile():
    db = get_db()
    user = db.execute("SELECT id, username, full_name, email, phone, department, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user:
        flash("User profile not found.")
        return redirect(url_for("dashboard"))
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>My Profile</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px 0; }
                .container { max-width: 600px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .profile-item { padding: 12px 0; border-bottom: 1px solid #e9ecef; }
                .profile-item:last-child { border-bottom: none; }
                .profile-label { font-weight: 600; color: #495057; }
                .profile-value { color: #212529; }
                .btn { border-radius: 5px; margin-top: 15px; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-secondary { background: #6c757d; border: none; }
                .badge { padding: 6px 12px; font-size: 0.9rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">👤 My Profile</h2>
                    </div>
                    <div class="card-body">
                        <div class="profile-item">
                            <div class="profile-label">Username</div>
                            <div class="profile-value">{{ user['username'] }}</div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Full Name</div>
                            <div class="profile-value">{{ user['full_name'] or '—' }}</div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Email</div>
                            <div class="profile-value">{{ user['email'] or '—' }}</div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Phone</div>
                            <div class="profile-value">{{ user['phone'] or '—' }}</div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Department</div>
                            <div class="profile-value">{{ user['department'] or '—' }}</div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Role</div>
                            <div class="profile-value"><span class="badge bg-primary">{{ user['role']|upper }}</span></div>
                        </div>
                        <div class="d-flex gap-2 mt-4">
                            <a href="{{ url_for('dashboard') }}" class="btn btn-secondary flex-grow-1">Back to Dashboard</a>
                            <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        user=user,
    )


@app.route("/dashboard")
@login_required()
def dashboard():
    db = get_db()
    user = db.execute("SELECT id, username, full_name, email, phone, department, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="app-shell">
                <aside class="sidebar">
                    <h2>Student Portal</h2>
                    <p class="text-muted">Welcome back, {{ user['full_name'] or username }}.</p>
                    <div class="nav-menu">
                        <a class="active" href="{{ url_for('dashboard') }}">Overview</a>
                        <a href="{{ url_for('assignments') }}">Assignments</a>
                        {% if role == 'admin' %}
                            <a href="{{ url_for('register') }}">Manage Users</a>
                        {% endif %}
                        {% if role in ['teacher', 'admin'] %}
                            <a href="{{ url_for('submissions') }}">Submissions</a>
                        {% endif %}
                        <a href="{{ url_for('logout') }}">Logout</a>
                    </div>
                </aside>
                <main class="main-content">
                    <div class="topbar">
                        <div>
                            <h1 class="h3">Dashboard</h1>
                            <p class="text-muted mb-0">A quick view of your account and activity.</p>
                        </div>
                        <div class="user-summary">
                            <div class="avatar">{{ (user['full_name'] or username)[:2].upper() }}</div>
                            <div>
                                <strong>{{ user['full_name'] or username }}</strong><br>
                                <span class="text-muted">{{ role.title() }}</span>
                            </div>
                        </div>
                    </div>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <h3>Role</h3>
                            <div class="value">{{ role.title() }}</div>
                        </div>
                        <div class="stat-card">
                            <h3>Department</h3>
                            <div class="value">{{ user['department'] or 'Not set' }}</div>
                        </div>
                        <div class="stat-card">
                            <h3>Email</h3>
                            <div class="value">{{ user['email'] or 'Not available' }}</div>
                        </div>
                        <div class="stat-card">
                            <h3>Phone</h3>
                            <div class="value">{{ user['phone'] or 'Not added' }}</div>
                        </div>
                    </div>
                    <div class="content-panel">
                        <section class="panel-card">
                            <h3>Your profile</h3>
                            <p class="text-muted">Important account details and quick links for your next action.</p>
                            <div class="profile-detail">
                                <strong>Username</strong><span>{{ username }}</span>
                                <strong>Full name</strong><span>{{ user['full_name'] or '—' }}</span>
                                <strong>Email</strong><span>{{ user['email'] or '—' }}</span>
                                <strong>Phone</strong><span>{{ user['phone'] or '—' }}</span>
                                <strong>Department</strong><span>{{ user['department'] or '—' }}</span>
                            </div>
                        </section>
                        <section class="panel-card">
                            <h3>Quick actions</h3>
                            <p class="text-muted">Jump to commonly used pages.</p>
                            <div class="list-group">
                                <a href="{{ url_for('assignments') }}" class="list-group-item list-group-item-action">View assignments</a>
                                {% if role == 'admin' %}
                                    <a href="{{ url_for('register') }}" class="list-group-item list-group-item-action">Manage users</a>
                                {% endif %}
                                {% if role in ['teacher', 'admin'] %}
                                    <a href="{{ url_for('submissions') }}" class="list-group-item list-group-item-action">Review submissions</a>
                                {% endif %}
                            </div>
                            <a href="{{ url_for('logout') }}" class="btn btn-secondary btn-pill w-100 mt-4">Sign out</a>
                        </section>
                    </div>
                </main>
            </div>
        </body>
        </html>
        """,
        username=session["username"],
        role=session["role"],
        user=user,
    )


@app.route("/register", methods=["GET", "POST"])
@login_required(["admin"])
def register():
    if request.method == "POST":
        db = get_db()
        user_file = request.files.get("user_file")
        if user_file and user_file.filename:
            ext = user_file.filename.rsplit(".", 1)[1].lower()
            if not allowed_user_upload(user_file.filename):
                flash("Uploaded file must be an Excel (.xlsx) or CSV file.")
            else:
                try:
                    rows = parse_user_upload(user_file, ext)
                    inserted = 0
                    skipped = 0
                    for row_data in rows:
                        username = (row_data.get("username") or "").strip()
                        role = (row_data.get("role") or "").strip().lower()
                        if not username or role not in ("student", "teacher", "admin"):
                            skipped += 1
                            continue
                        password_hash = generate_password_hash(username)
                        password_changed = 0 if role in ("student", "teacher") else 1
                        full_name = (row_data.get("full_name") or "").strip()
                        email = (row_data.get("email") or "").strip()
                        phone = (row_data.get("phone") or "").strip()
                        department = (row_data.get("department") or "").strip()
                        try:
                            db_execute(
                                db,
                                "INSERT INTO users(username, password, role, password_changed, full_name, email, phone, department, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
                                (username, password_hash, role, password_changed, full_name, email, phone, department),
                                commit=True,
                            )
                            inserted += 1
                        except sqlite3.IntegrityError:
                            skipped += 1
                    if inserted:
                        flash(f"Imported {inserted} users. {skipped} invalid or duplicate rows were skipped.")
                    else:
                        flash("No valid users found in upload.")
                except Exception as e:
                    flash(f"Upload failed: {str(e)}")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role")
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            department = request.form.get("department", "").strip()
            if not username or not password or role not in ("student", "teacher", "admin"):
                flash("All fields are required and role must be valid.")
            else:
                if role in ("student", "teacher"):
                    password_hash = generate_password_hash(username)
                    password_changed = 0
                else:
                    password_hash = generate_password_hash(password)
                    password_changed = 1
                try:
                    db_execute(
                        db,
                        "INSERT INTO users(username, password, role, password_changed, full_name, email, phone, department, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))",
                        (username, password_hash, role, password_changed, full_name, email, phone, department),
                        commit=True,
                    )
                    flash("User created.")
                except sqlite3.IntegrityError:
                    flash("Username already exists.")
    db = get_db()
    search_q = request.args.get('q', '').strip()
    if search_q:
        like = f"%{search_q}%"
        users = db.execute(
            "SELECT id, username, role, full_name, email, department FROM users WHERE username LIKE ? OR full_name LIKE ? OR email LIKE ? OR department LIKE ? ORDER BY created_at DESC",
            (like, like, like, like),
        ).fetchall()
    else:
        users = db.execute("SELECT id, username, role, full_name, email, department FROM users ORDER BY created_at DESC").fetchall()
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Manage Users</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px 0; }
                .container { max-width: 1000px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
                .btn-sm { font-size: 0.8rem; padding: 0.3rem 0.6rem; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Manage Users</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-success">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        <ul class="nav nav-tabs mb-3" role="tablist">
                            <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#import">Import Users</a></li>
                            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#create">Create User</a></li>
                        </ul>
                        <div class="tab-content mb-4">
                            <div id="import" class="tab-pane fade show active">
                                <form method="post" enctype="multipart/form-data" class="mb-3">
                                    <div class="mb-3">
                                        <label class="form-label">Upload Excel/CSV</label>
                                        <input class="form-control" type="file" name="user_file" accept=".xlsx,.csv">
                                        <small class="text-muted">File should contain username and role columns.</small>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Import Users</button>
                                </form>
                            </div>
                            <div id="create" class="tab-pane fade">
                                <form method="post" class="mb-3">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Username <span class="text-danger">*</span></label>
                                                <input class="form-control" name="username" required>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Password <span class="text-danger">*</span></label>
                                                <input class="form-control" type="password" name="password" required>
                                                <small class="form-text text-muted">For students/teachers, default is username.</small>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Full Name</label>
                                                <input class="form-control" name="full_name">
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Email</label>
                                                <input class="form-control" type="email" name="email">
                                            </div>
                                        </div>
                                    </div>
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Phone</label>
                                                <input class="form-control" name="phone">
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="mb-3">
                                                <label class="form-label">Department</label>
                                                <input class="form-control" name="department">
                                            </div>
                                        </div>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">Role <span class="text-danger">*</span></label>
                                        <select class="form-select" name="role" required>
                                            <option value="">Select Role</option>
                                            <option value="student">Student</option>
                                            <option value="teacher">Teacher</option>
                                            <option value="admin">Admin</option>
                                        </select>
                                    </div>
                                    <button type="submit" class="btn btn-primary w-100">Create User</button>
                                </form>
                            </div>
                        </div>
                        <h5 class="mb-3">Existing Users</h5>
                        <form method="get" class="mb-3">
                            <div class="input-group">
                                <input type="text" name="q" class="form-control" placeholder="Search username, full name, email or department" value="{{ q or '' }}">
                                <button class="btn btn-outline-secondary" type="submit">Search</button>
                                <a href="{{ url_for('register') }}" class="btn btn-outline-secondary">Clear</a>
                            </div>
                        </form>
                        <div class="mb-2 d-flex gap-2">
                            <form method="post" action="{{ url_for('delete_imported_users') }}" onsubmit="return confirm('Delete all imported users (students/lecturers with default password)?');" style="margin:0;">
                                <button type="submit" class="btn btn-warning btn-sm">Delete Imported Users</button>
                            </form>
                            <a href="{{ url_for('preview_blocking_users') }}" class="btn btn-outline-info btn-sm">Preview Blocking Users</a>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-hover table-sm">
                                <thead class="table-light">
                                    <tr>
                                        <th>Username</th>
                                        <th>Full Name</th>
                                        <th>Email</th>
                                        <th>Department</th>
                                        <th>Role</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for user in users %}
                                        <tr>
                                            <td><strong>{{ user['username'] }}</strong></td>
                                            <td>{{ user['full_name'] or '-' }}</td>
                                            <td>{{ user['email'] or '-' }}</td>
                                            <td>{{ user['department'] or '-' }}</td>
                                            <td><span class="badge bg-info">{{ user['role'] }}</span></td>
                                            <td>
                                                <a href="{{ url_for('edit_user', user_id=user['id']) }}" class="btn btn-outline-primary btn-sm">Edit</a>
                                                <a href="{{ url_for('delete_user', user_id=user['id']) }}" class="btn btn-outline-danger btn-sm" onclick="return confirm('Delete {{ user[\"username\"] }}?')">Delete</a>
                                            </td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </html>
        """,
        users=users,
        q=search_q,
    )


@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required(["admin"])
def edit_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.")
        return redirect(url_for("register"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        role = request.form.get("role")
        if not username or role not in ("student", "teacher", "admin"):
            flash("Invalid input.")
        else:
            try:
                db_execute(
                    db,
                    "UPDATE users SET username = ?, full_name = ?, email = ?, phone = ?, department = ?, role = ?, updated_at = datetime('now') WHERE id = ?",
                    (username, full_name, email, phone, department, role, user_id),
                    commit=True,
                )
                flash("User updated successfully.")
                return redirect(url_for("register"))
            except sqlite3.IntegrityError:
                flash("Username already in use.")
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Edit User</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px 0; }
                .container { max-width: 600px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Edit User</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-info">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        <form method="post">
                            <div class="mb-3">
                                <label class="form-label">Username <span class="text-danger">*</span></label>
                                <input class="form-control" name="username" value="{{ user['username'] }}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Full Name</label>
                                <input class="form-control" name="full_name" value="{{ user['full_name'] or '' }}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Email</label>
                                <input class="form-control" type="email" name="email" value="{{ user['email'] or '' }}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Phone</label>
                                <input class="form-control" name="phone" value="{{ user['phone'] or '' }}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Department</label>
                                <input class="form-control" name="department" value="{{ user['department'] or '' }}">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Role <span class="text-danger">*</span></label>
                                <select class="form-select" name="role" required>
                                    <option value="student" {% if user['role'] == 'student' %}selected{% endif %}>Student</option>
                                    <option value="teacher" {% if user['role'] == 'teacher' %}selected{% endif %}>Teacher</option>
                                    <option value="admin" {% if user['role'] == 'admin' %}selected{% endif %}>Admin</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Update User</button>
                            <a href="{{ url_for('register') }}" class="btn btn-secondary w-100 mt-2">Cancel</a>
                        </form>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        user=user,
    )


@app.route("/delete_user/<int:user_id>", methods=["GET"])
@login_required(["admin"])
def delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.")
    elif user_id == session.get("user_id"):
        flash("Cannot delete your own account.")
    else:
        # Check for dependent rows to avoid FOREIGN KEY constraint failures
        try:
            sub_row = db.execute("SELECT COUNT(*) AS cnt FROM submissions WHERE student_id = ?", (user_id,)).fetchone()
            assign_row = db.execute("SELECT COUNT(*) AS cnt FROM assignments WHERE created_by = ?", (user_id,)).fetchone()
            sub_cnt = sub_row["cnt"] if sub_row else 0
            assign_cnt = assign_row["cnt"] if assign_row else 0
            if sub_cnt > 0 or assign_cnt > 0:
                parts = []
                if sub_cnt > 0:
                    parts.append(f"{sub_cnt} submission(s)")
                if assign_cnt > 0:
                    parts.append(f"{assign_cnt} assignment(s)")
                flash(f"Cannot delete user '{user['username']}' — has dependent records: " + ", ".join(parts) + ". Reassign or remove those first.")
            else:
                db_execute(db, "DELETE FROM users WHERE id = ?", (user_id,), commit=True)
                flash(f"User '{user['username']}' deleted successfully.")
        except Exception as e:
            flash(f"Error deleting user: {str(e)}")
    return redirect(url_for("register"))
 
@app.route("/delete_imported_users", methods=["POST"])
@login_required(["admin"])
def delete_imported_users():
    db = get_db()
    # find imported users: students/teachers with password_changed == 0
    rows = db.execute(
        "SELECT id, username, role FROM users WHERE role IN ('student','teacher') AND password_changed = 0"
    ).fetchall()
    if not rows:
        flash("No imported users found to delete.")
        return redirect(url_for("register"))

    deleted = 0
    skipped = []
    for r in rows:
        uid = r["id"]
        uname = r["username"]
        # check for dependent rows that would violate FK constraints
        sub_row = db.execute("SELECT COUNT(*) AS cnt FROM submissions WHERE student_id = ?", (uid,)).fetchone()
        assign_row = db.execute("SELECT COUNT(*) AS cnt FROM assignments WHERE created_by = ?", (uid,)).fetchone()
        sub_cnt = sub_row["cnt"] if sub_row else 0
        assign_cnt = assign_row["cnt"] if assign_row else 0
        if sub_cnt > 0 or assign_cnt > 0:
            skipped.append({"id": uid, "username": uname, "submissions": sub_cnt, "assignments": assign_cnt})
            continue
        try:
            db_execute(db, "DELETE FROM users WHERE id = ?", (uid,), commit=True)
            deleted += 1
        except Exception as e:
            skipped.append({"id": uid, "username": uname, "error": str(e)})

    msg_parts = []
    if deleted:
        msg_parts.append(f"Deleted {deleted} imported user(s).")
    if skipped:
        msg_parts.append(f"Skipped {len(skipped)} user(s) with dependent records (submissions/assignments) or errors.")
    flash(" ".join(msg_parts))
    return redirect(url_for("register"))


@app.route("/preview_blocking_users")
@login_required(["admin"])
def preview_blocking_users():
        db = get_db()
        rows = db.execute(
                """
                SELECT u.id, u.username, u.role,
                    (SELECT COUNT(*) FROM submissions s WHERE s.student_id = u.id) AS submissions,
                    (SELECT COUNT(*) FROM assignments a WHERE a.created_by = u.id) AS assignments
                FROM users u
                WHERE u.role IN ('student','teacher') AND u.password_changed = 0
                """
        ).fetchall()
        # only show those with dependent records
        blocking = [r for r in rows if (r["submissions"] and r["submissions"] > 0) or (r["assignments"] and r["assignments"] > 0)]
        return render_template_with_watermark(
                """
                <!DOCTYPE html>
                <html>
                <head>
                        <title>Blocking Imported Users</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                        <style> body { background: #0b1220; color: #eef3ff; min-height:100vh; padding:30px; } .card{background:rgba(8,14,28,0.95);}</style>
                </head>
                <body>
                        <div class="container">
                                <div class="card">
                                        <div class="card-header">
                                                <h3 class="mb-0">Imported Users With Dependent Records</h3>
                                        </div>
                                        <div class="card-body">
                                                {% with messages = get_flashed_messages() %}
                                                    {% if messages %}
                                                        <div class="alert alert-info">{{ messages[0] }}</div>
                                                    {% endif %}
                                                {% endwith %}
                                                {% if users %}
                                                <div class="table-responsive">
                                                    <table class="table table-sm table-hover">
                                                        <thead class="table-light">
                                                            <tr><th>ID</th><th>Username</th><th>Role</th><th>Submissions</th><th>Assignments</th><th>Actions</th></tr>
                                                        </thead>
                                                        <tbody>
                                                            {% for u in users %}
                                                                <tr>
                                                                    <td>{{ u['id'] }}</td>
                                                                    <td><strong>{{ u['username'] }}</strong></td>
                                                                    <td>{{ u['role'] }}</td>
                                                                    <td>{{ u['submissions'] }}</td>
                                                                    <td>{{ u['assignments'] }}</td>
                                                                    <td>
                                                                        <a href="{{ url_for('edit_user', user_id=u['id']) }}" class="btn btn-outline-primary btn-sm">Edit</a>
                                                                        <form method="post" action="{{ url_for('delete_user_submissions', user_id=u['id']) }}" style="display:inline; margin-left:6px;">
                                                                            <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Delete all submissions for this user?');">Delete submissions</button>
                                                                        </form>
                                                                        <form method="post" action="{{ url_for('reassign_user_submissions', user_id=u['id']) }}" style="display:inline; margin-left:6px;">
                                                                            <button type="submit" class="btn btn-outline-warning btn-sm" onclick="return confirm('Reassign submissions to placeholder user?');">Reassign</button>
                                                                        </form>
                                                                        <form method="post" action="{{ url_for('force_delete_user', user_id=u['id']) }}" style="display:inline; margin-left:6px;">
                                                                            <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Force delete user and all dependents? This is irreversible.');">Force Delete</button>
                                                                        </form>
                                                                    </td>
                                                                </tr>
                                                            {% endfor %}
                                                        </tbody>
                                                    </table>
                                                </div>
                                                {% else %}
                                                    <div class="alert alert-secondary">No blocking users found.</div>
                                                {% endif %}
                                                <a href="{{ url_for('register') }}" class="btn btn-secondary mt-3">Back to Manage Users</a>
                                        </div>
                                </div>
                        </div>
                </body>
                </html>
                """,
                users=blocking,
        )


@app.route('/delete_user_submissions/<int:user_id>', methods=['POST'])
@login_required(['admin'])
def delete_user_submissions(user_id):
    db = get_db()
    row = db.execute('SELECT COUNT(*) AS cnt FROM submissions WHERE student_id = ?', (user_id,)).fetchone()
    cnt = row['cnt'] if row else 0
    if cnt == 0:
        flash('No submissions found for that user.')
        return redirect(url_for('preview_blocking_users'))
    try:
        db_execute(db, 'DELETE FROM submissions WHERE student_id = ?', (user_id,), commit=True)
        flash(f'Deleted {cnt} submission(s) for the user.')
    except Exception as e:
        flash(f'Error deleting submissions: {str(e)}')
    return redirect(url_for('preview_blocking_users'))


@app.route('/reassign_user_submissions/<int:user_id>', methods=['POST'])
@login_required(['admin'])
def reassign_user_submissions(user_id):
    db = get_db()
    placeholder = db.execute("SELECT id FROM users WHERE username = ?", ('deleted_user',)).fetchone()
    if not placeholder:
        try:
            db_execute(db, "INSERT INTO users(username,password,role,password_changed,full_name,created_at,updated_at) VALUES (?,?,?,?,?,datetime('now'),datetime('now'))",
                       ('deleted_user', generate_password_hash('deleted_user'), 'teacher', 1, 'Deleted User'), commit=True)
            placeholder = db.execute("SELECT id FROM users WHERE username = ?", ('deleted_user',)).fetchone()
        except Exception as e:
            flash(f'Error creating placeholder user: {str(e)}')
            return redirect(url_for('preview_blocking_users'))
    pid = placeholder['id']
    try:
        db_execute(db, 'UPDATE submissions SET student_id = ? WHERE student_id = ?', (pid, user_id), commit=True)
        flash('Reassigned submissions to placeholder user.')
    except Exception as e:
        flash(f'Error reassigning submissions: {str(e)}')
    return redirect(url_for('preview_blocking_users'))


@app.route('/force_delete_user/<int:user_id>', methods=['POST'])
@login_required(['admin'])
def force_delete_user(user_id):
    db = get_db()
    try:
        # delete dependents first
        db_execute(db, 'DELETE FROM submissions WHERE student_id = ?', (user_id,), commit=True)
        db_execute(db, 'DELETE FROM assignments WHERE created_by = ?', (user_id,), commit=True)
        db_execute(db, 'DELETE FROM users WHERE id = ?', (user_id,), commit=True)
        flash('Deleted user and all dependents.')
    except Exception as e:
        flash(f'Error force-deleting user: {str(e)}')
    return redirect(url_for('preview_blocking_users'))


@app.route("/assignments", methods=["GET", "POST"])
@login_required()
def assignments():
    db = get_db()
    role = session["role"]
    if request.method == "POST":
        if role not in ["teacher", "admin"]:
            flash("Access denied.")
        else:
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            due_date = request.form.get("due_date", "").strip()
            if not title or not description or not due_date:
                flash("All assignment fields are required.")
            else:
                db_execute(
                    db,
                    "INSERT INTO assignments(title, description, due_date, created_by) VALUES (?, ?, ?, ?)",
                    (title, description, due_date, session["user_id"]),
                    commit=True,
                )
                flash("Assignment created.")
    assignments = db.execute("SELECT * FROM assignments ORDER BY id DESC").fetchall()
    user_submissions = {}
    if role == "student":
        rows = db.execute(
            "SELECT assignment_id, filename FROM submissions WHERE student_id = ?", (session["user_id"],)
        ).fetchall()
        user_submissions = {row["assignment_id"]: row["filename"] for row in rows}
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Assignments</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px 0; }
                .container { max-width: 900px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); margin-bottom: 20px; }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
                .assignment-card { border-left: 5px solid #667eea; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Assignments</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-success">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        {% if role in ['teacher', 'admin'] %}
                            <div class="card mb-4 assignment-card">
                                <div class="card-header bg-light">
                                    <h5 class="mb-0 text-dark">Create New Assignment</h5>
                                </div>
                                <div class="card-body">
                                    <form method="post">
                                        <div class="mb-3">
                                            <label class="form-label">Title</label>
                                            <input class="form-control" name="title" required>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Description</label>
                                            <textarea class="form-control" name="description" rows="3" required></textarea>
                                        </div>
                                        <div class="mb-3">
                                            <label class="form-label">Due Date</label>
                                            <input class="form-control" type="date" name="due_date" required>
                                        </div>
                                        <button type="submit" class="btn btn-primary">Create Assignment</button>
                                    </form>
                                </div>
                            </div>
                        {% endif %}
                        <h5>Available Assignments</h5>
                        {% for assignment in assignments %}
                            <div class="card assignment-card mb-3">
                                <div class="card-body">
                                    <h5 class="card-title">{{ assignment['title'] }}</h5>
                                    <p class="card-text">{{ assignment['description'] }}</p>
                                    <p class="text-muted"><strong>Due:</strong> {{ assignment['due_date'] }}</p>
                                    {% if role == 'student' %}
                                        {% if assignment['id'] in user_submissions %}
                                            <span class="badge bg-success">✓ Submitted: {{ user_submissions[assignment['id']] }}</span>
                                        {% else %}
                                            <a href="{{ url_for('upload', assignment_id=assignment['id']) }}" class="btn btn-primary btn-sm">Upload</a>
                                        {% endif %}
                                    {% endif %}
                                </div>
                            </div>
                        {% endfor %}
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100">Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        assignments=assignments,
        role=role,
        user_submissions=user_submissions,
    )


@app.route("/upload/<int:assignment_id>", methods=["GET", "POST"])
@login_required(["student"])
def upload(assignment_id):
    db = get_db()
    assignment = db.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
    if not assignment:
        flash("Assignment not found.")
        return redirect(url_for("assignments"))
    if request.method == "POST":
        file = request.files.get("file")
        error = validate_upload(file)
        if error:
            flash(error)
        else:
            filename = secure_filename(file.filename)
            student_prefix = f"student_{session['user_id']}_assign_{assignment_id}_"
            save_name = student_prefix + filename
            path = os.path.join(app.config["UPLOAD_FOLDER"], save_name)
            file.save(path)
            db_execute(
                db,
                "INSERT INTO submissions(assignment_id, student_id, filename, uploaded_at) VALUES (?, ?, ?, datetime('now'))",
                (assignment_id, session["user_id"], save_name),
                commit=True,
            )
            flash("Upload successful.")
            return redirect(url_for("assignments"))
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Upload Assignment</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; }
                .container { max-width: 500px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
                .custom-file-input { cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Upload Submission</h2>
                    </div>
                    <div class="card-body">
                        <p><strong>Assignment:</strong> {{ assignment['title'] }}</p>
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-danger">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        <form method="post" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label class="form-label">Select File</label>
                                <input class="form-control" type="file" name="file" required>
                                <small class="text-muted">Allowed: pdf, doc, docx, txt, zip (Max 16MB)</small>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Upload</button>
                        </form>
                        <a href="{{ url_for('assignments') }}" class="btn btn-secondary w-100 mt-3">Back to Assignments</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        assignment=assignment,
    )


@app.route("/submissions", methods=["GET", "POST"])
@login_required(["teacher", "admin"])
def submissions():
    db = get_db()
    if request.method == "POST":
        sub_id = request.form.get("submission_id")
        grade = request.form.get("grade", "").strip()
        feedback = request.form.get("feedback", "").strip()
        if sub_id and grade:
            db_execute(
                db,
                "UPDATE submissions SET grade = ?, feedback = ? WHERE id = ?",
                (grade, feedback, sub_id),
                commit=True,
            )
            flash("Grade updated.")
    rows = db.execute(
        "SELECT s.id, a.title AS assignment, u.username AS student, s.filename, s.uploaded_at, s.grade, s.feedback"
        " FROM submissions s"
        " JOIN assignments a ON s.assignment_id = a.id"
        " JOIN users u ON s.student_id = u.id"
        " ORDER BY s.uploaded_at DESC"
    ).fetchall()
    return render_template_with_watermark(
        """
        <!DOCTYPE html>
        <html>
            <head>
            <title>Submissions</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 30px 0; }
                .container { max-width: 1000px; }
                .card { border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
                .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px 10px 0 0; }
                .submission-card { border-left: 5px solid #667eea; margin-bottom: 15px; }
                .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: none; }
                .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
                .form-group { margin-bottom: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-header">
                        <h2 class="mb-0">Student Submissions</h2>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                          {% if messages %}
                            <div class="alert alert-success">{{ messages[0] }}</div>
                          {% endif %}
                        {% endwith %}
                        {% for row in rows %}
                            <div class="card submission-card">
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-md-8">
                                            <h5 class="card-title">{{ row['assignment'] }}</h5>
                                            <p class="text-muted"><strong>Student:</strong> {{ row['student'] }}</p>
                                            <p class="text-muted"><strong>File:</strong> {{ row['filename'] }}</p>
                                            <p class="text-muted"><strong>Uploaded:</strong> {{ row['uploaded_at'] }}</p>
                                        </div>
                                        <div class="col-md-4">
                                            <a href="{{ url_for('preview', submission_id=row['id']) }}" target="_blank" class="btn btn-outline-secondary btn-sm w-100 mb-2">Preview</a>
                                            <form method="post" class="border-start ps-3">
                                                <input type="hidden" name="submission_id" value="{{ row['id'] }}">
                                                <div class="form-group">
                                                    <label class="form-label">Grade</label>
                                                    <input class="form-control form-control-sm" name="grade" value="{{ row['grade'] or '' }}" placeholder="e.g., A+">
                                                </div>
                                                <div class="form-group">
                                                    <label class="form-label">Feedback</label>
                                                    <input class="form-control form-control-sm" name="feedback" value="{{ row['feedback'] or '' }}" placeholder="Your feedback">
                                                </div>
                                                <button type="submit" class="btn btn-primary btn-sm w-100">Save Grade</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back to Dashboard</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """,
        rows=rows,
    )

if __name__ == "__main__":
    # try to ensure openpyxl is available at startup (best-effort)
    ensure_openpyxl()
    with app.app_context():
        init_db()
    app.run(debug=True)

