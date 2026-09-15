import os
import secrets
import sqlite3
from contextlib import closing
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template_string,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get("APP_DATABASE", str(Path(__file__).with_name("service.db"))),
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=16 * 1024,
)

# 세션 서명 키도 DB에 보관하여 서버를 재시작해도 로그인이 유지됩니다.
with closing(sqlite3.connect(app.config["DATABASE"])) as db:
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            clicks INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    db.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        ("secret_key", secrets.token_hex(32)),
    )
    db.commit()
    app.secret_key = os.environ.get("SECRET_KEY") or db.execute(
        "SELECT value FROM settings WHERE key = ?", ("secret_key",)
    ).fetchone()[0]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def load_user_and_check_csrf():
    g.user = get_db().execute(
        "SELECT id, username, clicks FROM users WHERE id = ?",
        (session.get("user_id"),),
    ).fetchone()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    if request.method == "POST" and not secrets.compare_digest(
        session["csrf_token"], request.form.get("csrf_token", "")
    ):
        abort(400, description="요청이 만료되었습니다. 새로고침 후 다시 시도해 주세요.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("먼저 로그인해 주세요.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


HTML = """
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>무쓸모 — 아무 일도 안 하는 서비스</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; background: #f4f1e9; color: #242820;
           font-family: system-ui, sans-serif; line-height: 1.6; }
    main { width: min(100% - 32px, 480px); margin: 64px auto; }
    nav { display: flex; justify-content: space-between; align-items: center; }
    a { color: #365d3a; text-underline-offset: 4px; }
    .brand { font-weight: 900; font-size: 24px; text-decoration: none; }
    section { margin-top: 28px; padding: 30px; background: #fffdf7;
              border: 1px solid #d9d8ca; border-radius: 16px; }
    h1 { font-size: 28px; line-height: 1.3; margin-top: 0; }
    p, small { color: #62665c; }
    label { display: block; margin-top: 18px; font-weight: 600; }
    input { width: 100%; padding: 12px; margin-top: 6px; font: inherit;
            border: 1px solid #acae9d; border-radius: 8px; }
    button, .button { display: inline-block; padding: 12px 20px;
              border: 0; border-radius: 8px; background: #365d3a; color: white;
              font: inherit; cursor: pointer; text-decoration: none; }
    section button { width: 100%; margin-top: 24px; }
    nav button { padding: 6px 12px; background: transparent; color: #365d3a; }
    .message { padding: 12px; background: #e6ecd9; border-radius: 8px; }
    .count { font-size: 64px; font-weight: 800; margin: 20px 0 0; }
    footer { margin-top: 24px; font-size: 13px; color: #62665c; text-align: center; }
    :focus-visible { outline: 3px solid #b78a35; outline-offset: 3px; }
  </style>
</head>
<body>
<main>
  <nav>
    <a class="brand" href="{{ url_for('index') }}">무쓸모.</a>
    {% if g.user %}
    <form method="post" action="{{ url_for('logout') }}">
      <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
      <button type="submit">로그아웃</button>
    </form>
    {% else %}<a href="{{ url_for('login') }}">로그인</a>{% endif %}
  </nav>
  {% for message in get_flashed_messages() %}
    <p class="message" role="status">{{ message }}</p>
  {% endfor %}
  <section>
  {% if page in ('register', 'login') %}
    <h1>{{ '회원가입' if page == 'register' else '로그인' }}</h1>
    <p>아무것도 이루지 않을 준비가 되셨나요?</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
      <label for="username">아이디</label>
      <input id="username" name="username" required minlength="3" maxlength="30"
             autocomplete="username" value="{{ request.form.get('username', '') }}">
      <label for="password">비밀번호</label>
      <input id="password" name="password" type="password" required
             minlength="8" maxlength="128"
             autocomplete="{{ 'new-password' if page == 'register' else 'current-password' }}">
      <small>아이디 3~30자 · 비밀번호 8~128자</small>
      <button type="submit">{{ '회원가입' if page == 'register' else '로그인' }}</button>
    </form>
    <p><a href="{{ url_for('login' if page == 'register' else 'register') }}">
      {{ '이미 계정이 있으신가요? 로그인' if page == 'register' else '계정이 없으신가요? 회원가입' }}
    </a></p>
  {% elif g.user %}
    <h1>{{ g.user.username }}님,<br>오늘도 무의미하게.</h1>
    <p>버튼을 누르면 숫자가 올라갑니다. 그게 전부입니다.</p>
    <div class="count">{{ g.user.clicks }}</div>
    <small>번의 클릭 · 이룬 것 0개</small>
    <form method="post" action="{{ url_for('click') }}">
      <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
      <button type="submit">아무 일도 안 하기 +1</button>
    </form>
  {% else %}
    <h1>아무 일도<br>일어나지 않습니다.</h1>
    <p>회원가입까지 했는데 할 수 있는 건 버튼 누르기뿐.<br>
       당신의 쓸데없는 클릭을 정성껏 보관합니다.</p>
    <a class="button" href="{{ url_for('register') }}">쓸데없이 시작하기</a>
  {% endif %}
  </section>
  <footer>무쓸모 — 생산성 0%를 지향합니다.</footer>
</main>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML, page="index")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 30 or not 8 <= len(password) <= 128:
            flash("아이디는 3~30자, 비밀번호는 8~128자로 입력해 주세요.")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                flash("이미 사용 중인 아이디입니다.")
            else:
                flash("회원가입이 완료되었습니다. 로그인해 주세요.")
                return redirect(url_for("login"))
    return render_template_string(HTML, page="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (request.form.get("username", "").strip(),),
        ).fetchone()
        password = request.form.get("password", "")
        if user and 8 <= len(password) <= 128 and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(url_for("index"))
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template_string(HTML, page="login")


@app.post("/logout")
@login_required
def logout():
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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
