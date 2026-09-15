import hashlib
import ipaddress
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.exceptions import TooManyRequests
from werkzeug.security import check_password_hash, generate_password_hash


def env_flag(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.lower() in {"1", "true", "yes", "on"}


def env_int(name, default, minimum=1):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"{name} must be an integer") from error
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def validate_admin_password(password):
    if password is None:
        raise RuntimeError(
            "A fresh database requires ADMIN_PASSWORD with at least 16 characters"
        )
    if not 16 <= len(password) <= 128:
        raise RuntimeError("ADMIN_PASSWORD must contain 16 to 128 characters")


def initial_admin_memo(configured_value=None):
    if configured_value is not None:
        if (
            not configured_value.startswith("SBOB" + "{")
            or not configured_value.endswith("}")
            or not 8 <= len(configured_value) <= 256
        ):
            raise RuntimeError("ADMIN_MEMO must use the required flag form")
        return configured_value
    return "SBOB" + "{" + "kmj_" + secrets.token_hex(24) + "}"


def ensure_private_file(path):
    path = Path(path).absolute()
    if str(path) == ":memory:" or str(path).startswith("file:"):
        raise RuntimeError("APP_DATABASE must be a regular filesystem path")
    if not path.parent.is_dir():
        raise RuntimeError(f"Database directory does not exist: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("APP_DATABASE must be a regular non-symlink file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RuntimeError("APP_DATABASE must be owned by the application user")
        path.chmod(0o600)
    else:
        os.close(descriptor)
    return path


def connect_database(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database(path, admin_password=None, admin_memo=None):
    database_path = ensure_private_file(path)
    old_umask = os.umask(0o077)
    try:
        with closing(connect_database(database_path)) as db:
            users_table_exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'"
            ).fetchone()
            old_user_columns = (
                {row[1] for row in db.execute("PRAGMA table_info(users)")}
                if users_table_exists else set()
            )
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    clicks INTEGER NOT NULL DEFAULT 0,
                    is_admin INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY,
                    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS auth_sessions_user_id ON auth_sessions(user_id);
                CREATE TABLE IF NOT EXISTS rate_limits (
                    scope TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    window_id INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY (scope, key_hash, window_id)
                );
            """)
            rate_limit_columns = {row[1] for row in db.execute("PRAGMA table_info(rate_limits)")}
            if "expires_at" not in rate_limit_columns:
                db.execute("ALTER TABLE rate_limits ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0")
            if users_table_exists and "is_admin" not in old_user_columns:
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

            admin = db.execute(
                "SELECT id, is_admin FROM users WHERE username = ?", ("admin",)
            ).fetchone()
            user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if admin is not None and not admin["is_admin"]:
                if (
                    "is_admin" not in old_user_columns
                    and admin_password is not None
                    and check_password_hash(
                        db.execute(
                            "SELECT password_hash FROM users WHERE id = ?", (admin["id"],)
                        ).fetchone()[0],
                        admin_password,
                    )
                ):
                    validate_admin_password(admin_password)
                    db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (admin["id"],))
                    admin = db.execute(
                        "SELECT id, is_admin FROM users WHERE id = ?", (admin["id"],)
                    ).fetchone()
                else:
                    raise RuntimeError(
                        "An unprivileged account named admin already exists; refusing automatic promotion"
                    )
            if admin is None and (user_count == 0 or admin_password is not None):
                validate_admin_password(admin_password)
                cursor = db.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                    ("admin", generate_password_hash(admin_password)),
                )
                db.execute(
                    "INSERT INTO notes (owner_id, content) VALUES (?, ?)",
                    (cursor.lastrowid, initial_admin_memo(admin_memo)),
                )

            if admin is not None:
                admin_hash = db.execute(
                    "SELECT password_hash FROM users WHERE id = ?", (admin["id"],)
                ).fetchone()[0]
                legacy_default = "admin" + "1234"
                if check_password_hash(admin_hash, legacy_default):
                    if admin_password is None or admin_password == legacy_default:
                        raise RuntimeError(
                            "The legacy default admin password must be rotated with ADMIN_PASSWORD"
                        )
                    validate_admin_password(admin_password)
                    db.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?",
                        (generate_password_hash(admin_password), admin["id"]),
                    )
                    db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (admin["id"],))

            db.execute("DELETE FROM settings WHERE key = ?", ("secret_key",))
            db.commit()
    finally:
        os.umask(old_umask)
    database_path.chmod(0o600)
    return database_path


def load_session_key(database_path):
    configured_key = os.environ.get("SECRET_KEY")
    if configured_key is not None:
        if len(configured_key) < 32:
            raise RuntimeError("SECRET_KEY must contain at least 32 characters")
        return configured_key
    key_path = Path(
        os.environ.get("APP_SESSION_KEY_FILE", str(database_path.with_name(".session.key")))
    ).absolute()
    if not key_path.parent.is_dir():
        raise RuntimeError(f"Session key directory does not exist: {key_path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(key_path, flags, 0o600)
    except FileExistsError:
        info = key_path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("Session key must be a regular non-symlink file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RuntimeError("Session key must be owned by the application user")
        key_path.chmod(0o600)
        key = key_path.read_text(encoding="ascii").strip()
    else:
        try:
            key = secrets.token_hex(32)
            os.write(descriptor, key.encode("ascii"))
        finally:
            os.close(descriptor)
    if len(key) < 64:
        raise RuntimeError("Session key file is invalid")
    return key


app = Flask(__name__)
is_production = os.environ.get("APP_ENV", "development") == "production"
trusted_hosts = [
    host.strip()
    for host in os.environ.get("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]
app.config.update(
    DATABASE=os.environ.get("APP_DATABASE", str(Path(__file__).with_name("service.db"))),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=env_flag("COOKIE_SECURE", is_production),
    SESSION_COOKIE_NAME="__Host-musulmo" if is_production else "musulmo_session",
    TRUSTED_HOSTS=trusted_hosts,
    MAX_CONTENT_LENGTH=16 * 1024,
    MAX_USERS=env_int("MAX_USERS", 10_000),
    LOGIN_IP_LIMIT=env_int("LOGIN_IP_LIMIT", 20),
    LOGIN_USER_LIMIT=env_int("LOGIN_USER_LIMIT", 5),
    LOGIN_GLOBAL_LIMIT=env_int("LOGIN_GLOBAL_LIMIT", 1_000),
    LOGIN_WINDOW_SECONDS=env_int("LOGIN_WINDOW_SECONDS", 15 * 60),
    REGISTER_IP_LIMIT=env_int("REGISTER_IP_LIMIT", 5),
    REGISTER_GLOBAL_LIMIT=env_int("REGISTER_GLOBAL_LIMIT", 100),
    REGISTER_WINDOW_SECONDS=env_int("REGISTER_WINDOW_SECONDS", 60 * 60),
    AUTH_SESSION_SECONDS=env_int("AUTH_SESSION_SECONDS", 30 * 60),
)
if is_production and not app.config["SESSION_COOKIE_SECURE"]:
    raise RuntimeError("Production requires COOKIE_SECURE=true")

os.umask(0o077)
database_path = initialize_database(
    app.config["DATABASE"], os.environ.get("ADMIN_PASSWORD"), os.environ.get("ADMIN_MEMO")
)
app.config["DATABASE"] = str(database_path)
app.secret_key = load_session_key(database_path)
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


def get_db():
    if "db" not in g:
        g.db = connect_database(app.config["DATABASE"])
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def enforce_rate_limit(scope, key, limit, window_seconds):
    now = int(time.time())
    window_id = now // window_seconds
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    db = get_db()
    expires_at = (window_id + 1) * window_seconds
    db.execute("DELETE FROM rate_limits WHERE expires_at <= ?", (now,))
    db.execute(
        """
        INSERT INTO rate_limits (scope, key_hash, window_id, attempts, expires_at)
        VALUES (?, ?, ?, 1, ?)
        ON CONFLICT(scope, key_hash, window_id)
        DO UPDATE SET attempts = attempts + 1, expires_at = excluded.expires_at
        """,
        (scope, key_hash, window_id, expires_at),
    )
    attempts = db.execute(
        "SELECT attempts FROM rate_limits WHERE scope = ? AND key_hash = ? AND window_id = ?",
        (scope, key_hash, window_id),
    ).fetchone()[0]
    db.commit()
    if attempts > limit:
        retry_after = (window_id + 1) * window_seconds - now
        raise TooManyRequests(
            description="요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
            retry_after=retry_after,
        )


def client_network_key(remote_address):
    try:
        address = ipaddress.ip_address(remote_address)
    except ValueError:
        return "unknown"
    if address.version == 6:
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


@app.before_request
def load_user_and_check_csrf():
    g.sensitive_response = False
    g.user = None
    user_id = session.get("user_id")
    auth_token = session.get("auth_token")
    if user_id is not None and auth_token:
        token_hash = hashlib.sha256(auth_token.encode("ascii")).hexdigest()
        g.user = get_db().execute(
            """
            SELECT users.id, users.username, users.clicks, users.is_admin
            FROM users JOIN auth_sessions ON auth_sessions.user_id = users.id
            WHERE users.id = ? AND auth_sessions.token_hash = ?
              AND auth_sessions.expires_at > ?
            """,
            (user_id, token_hash, int(time.time())),
        ).fetchone()
        if g.user is None:
            session.clear()
    elif user_id is not None or auth_token:
        session.clear()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    if request.method == "POST" and not secrets.compare_digest(
        session["csrf_token"], request.form.get("csrf_token", "")
    ):
        abort(400, description="요청이 만료되었습니다. 새로고침 후 다시 시도해 주세요.")


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if g.get("sensitive_response") or g.get("user") is not None or request.endpoint in {"login", "register"}:
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("먼저 로그인해 주세요.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        g.sensitive_response = True
        if not g.user["is_admin"]:
            abort(403, description="관리자만 접근할 수 있습니다.")
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    notes = []
    if g.user is not None:
        notes = get_db().execute(
            "SELECT id, content, created_at FROM notes WHERE owner_id = ? ORDER BY id DESC",
            (g.user["id"],),
        ).fetchall()
    return render_template("index.html", page="index", notes=notes)


@app.get("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id, username, clicks, is_admin FROM users ORDER BY id").fetchall()
    notes = db.execute(
        "SELECT content, created_at FROM notes WHERE owner_id = ? ORDER BY id", (g.user["id"],)
    ).fetchall()
    return render_template("admin.html", users=users, notes=notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        client_ip = client_network_key(request.remote_addr or "unknown")
        enforce_rate_limit(
            "register-global", "all", app.config["REGISTER_GLOBAL_LIMIT"],
            app.config["REGISTER_WINDOW_SECONDS"],
        )
        enforce_rate_limit("register-ip", client_ip, app.config["REGISTER_IP_LIMIT"], app.config["REGISTER_WINDOW_SECONDS"])
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 30 or not 12 <= len(password) <= 128:
            flash("아이디는 3~30자, 비밀번호는 12~128자로 입력해 주세요.")
            return render_template("index.html", page="register")

        db = get_db()
        at_capacity = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] >= app.config["MAX_USERS"]
        password_hash = None if at_capacity else generate_password_hash(password)
        if password_hash is not None:
            try:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] < app.config["MAX_USERS"]:
                    db.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, password_hash),
                    )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
        flash("가입 요청을 처리했습니다. 새 계정이라면 로그인해 주세요.")
        return redirect(url_for("login"))
    return render_template("index.html", page="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        client_ip = client_network_key(request.remote_addr or "unknown")
        enforce_rate_limit(
            "login-global", "all", app.config["LOGIN_GLOBAL_LIMIT"],
            app.config["LOGIN_WINDOW_SECONDS"],
        )
        enforce_rate_limit("login-ip", client_ip, app.config["LOGIN_IP_LIMIT"], app.config["LOGIN_WINDOW_SECONDS"])
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        enforce_rate_limit(
            "login-user", username, app.config["LOGIN_USER_LIMIT"],
            app.config["LOGIN_WINDOW_SECONDS"],
        )
        password_hash = user["password_hash"] if user is not None else DUMMY_PASSWORD_HASH
        valid_password = 1 <= len(password) <= 128 and check_password_hash(password_hash, password)
        if user is not None and valid_password:
            db = get_db()
            auth_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(auth_token.encode("ascii")).hexdigest()
            expires_at = int(time.time()) + app.config["AUTH_SESSION_SECONDS"]
            db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user["id"],))
            db.execute(
                "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user["id"], expires_at),
            )
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["auth_token"] = auth_token
            session.permanent = True
            return redirect(url_for("index"))
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template("index.html", page="login")


@app.post("/logout")
@login_required
def logout():
    db = get_db()
    db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (g.user["id"],))
    db.commit()
    session.clear()
    return redirect(url_for("index"))


@app.post("/click")
@login_required
def click():
    db = get_db()
    db.execute("UPDATE users SET clicks = clicks + 1 WHERE id = ?", (g.user["id"],))
    db.commit()
    flash("축하합니다. 여전히 아무 일도 일어나지 않았습니다.")
    return redirect(url_for("index"))


@app.post("/notes")
@login_required
def create_note():
    content = request.form.get("content", "").strip()
    if not 1 <= len(content) <= 1000:
        flash("메모는 1~1,000자로 입력해 주세요.")
        return redirect(url_for("index") + "#notes")

    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        note_count = db.execute(
            "SELECT COUNT(*) FROM notes WHERE owner_id = ?", (g.user["id"],)
        ).fetchone()[0]
        if note_count >= 100:
            db.rollback()
            flash("메모는 계정당 100개까지 저장할 수 있어요.")
            return redirect(url_for("index") + "#notes")
        db.execute(
            "INSERT INTO notes (owner_id, content) VALUES (?, ?)",
            (g.user["id"], content),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    flash("메모를 남겼어요.")
    return redirect(url_for("index") + "#notes")


@app.post("/notes/<int:note_id>/delete")
@login_required
def delete_note(note_id):
    db = get_db()
    cursor = db.execute(
        "DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, g.user["id"])
    )
    db.commit()
    if cursor.rowcount:
        flash("메모를 지웠어요.")
    return redirect(url_for("index") + "#notes")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
