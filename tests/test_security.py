import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path


TEST_DIR = tempfile.TemporaryDirectory()
TEST_DATABASE = Path(TEST_DIR.name) / "test.db"
os.environ["APP_DATABASE"] = str(TEST_DATABASE)
os.environ["APP_SESSION_KEY_FILE"] = str(Path(TEST_DIR.name) / "session.key")
os.environ["ADMIN_PASSWORD"] = "a-secure-admin-password"
os.environ["TRUSTED_HOSTS"] = "localhost"

import app as application


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        application.app.config.update(
            TESTING=True,
            LOGIN_IP_LIMIT=20,
            LOGIN_USER_LIMIT=5,
            LOGIN_GLOBAL_LIMIT=1_000,
            LOGIN_WINDOW_SECONDS=900,
            REGISTER_IP_LIMIT=5,
            REGISTER_GLOBAL_LIMIT=100,
            REGISTER_WINDOW_SECONDS=3600,
            MAX_USERS=10_000,
        )
        with application.app.app_context():
            db = application.get_db()
            db.execute("DELETE FROM rate_limits")
            db.execute("DELETE FROM auth_sessions")
            db.execute("DELETE FROM users WHERE username != 'admin'")
            db.commit()

    def csrf(self, client):
        client.get("/")
        with client.session_transaction() as current_session:
            return current_session["csrf_token"]

    def login(self, client, username="admin", password="a-secure-admin-password"):
        return client.post(
            "/login",
            data={"username": username, "password": password, "csrf_token": self.csrf(client)},
        )

    def register(self, client, username, password="a-secure-user-password"):
        return client.post(
            "/register",
            data={"username": username, "password": password, "csrf_token": self.csrf(client)},
        )

    def test_bootstrap_is_private_and_has_generated_memo(self):
        self.assertEqual(stat.S_IMODE(TEST_DATABASE.stat().st_mode), 0o600)
        with application.app.app_context():
            db = application.get_db()
            admin = db.execute("SELECT id, is_admin FROM users WHERE username='admin'").fetchone()
            memo = db.execute("SELECT content FROM notes WHERE owner_id=?", (admin["id"],)).fetchone()[0]
        self.assertEqual(admin["is_admin"], 1)
        self.assertTrue(memo.startswith("SBOB" + "{"))
        self.assertTrue(memo.endswith("}"))

    def test_admin_authorization_and_sensitive_cache_headers(self):
        member = application.app.test_client()
        self.register(member, "member-one")
        self.login(member, "member-one", "a-secure-user-password")
        denied = member.get("/admin")
        self.assertEqual(denied.status_code, 403)
        self.assertIn("no-store", denied.headers["Cache-Control"])
        admin = application.app.test_client()
        self.login(admin)
        allowed = admin.get("/admin")
        self.assertEqual(allowed.status_code, 200)
        self.assertIn("member-one", allowed.get_data(as_text=True))
        self.assertIn("no-store", allowed.headers["Cache-Control"])

    def test_login_rate_limit_and_retry_after(self):
        application.app.config["LOGIN_USER_LIMIT"] = 2
        client = application.app.test_client()
        token = self.csrf(client)
        for _ in range(2):
            response = client.post("/login", data={"username":"admin", "password":"wrong", "csrf_token":token})
            self.assertEqual(response.status_code, 200)
        limited = client.post("/login", data={"username":"admin", "password":"wrong", "csrf_token":token})
        self.assertEqual(limited.status_code, 429)
        self.assertIn("Retry-After", limited.headers)

    def test_login_name_limit_is_uniform_across_clients(self):
        application.app.config["LOGIN_USER_LIMIT"] = 1
        first = application.app.test_client()
        first.post(
            "/login", environ_base={"REMOTE_ADDR":"192.0.2.1"},
            data={"username":"admin", "password":"wrong", "csrf_token":self.csrf(first)},
        )
        second = application.app.test_client()
        limited = second.post(
            "/login", environ_base={"REMOTE_ADDR":"192.0.2.2"},
            data={"username":"admin", "password":"wrong", "csrf_token":self.csrf(second)},
        )
        self.assertEqual(limited.status_code, 429)

    def test_registration_is_limited_and_duplicate_response_is_uniform(self):
        first = application.app.test_client()
        first_response = self.register(first, "same-user")
        duplicate = application.app.test_client()
        duplicate_response = self.register(duplicate, "same-user")
        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(duplicate_response.status_code, 302)
        self.assertEqual(first_response.headers["Location"], duplicate_response.headers["Location"])
        application.app.config["REGISTER_IP_LIMIT"] = 1
        with application.app.app_context():
            application.get_db().execute("DELETE FROM rate_limits")
            application.get_db().commit()
        client = application.app.test_client()
        self.register(client, "rate-one")
        self.assertEqual(self.register(client, "rate-two").status_code, 429)

    def test_logout_revokes_a_copied_session(self):
        original = application.app.test_client()
        self.login(original)
        cookie_name = application.app.config["SESSION_COOKIE_NAME"]
        cookie = original.get_cookie(cookie_name)
        copied = application.app.test_client()
        copied.set_cookie(cookie_name, cookie.value, domain="localhost")
        original.post("/logout", data={"csrf_token":self.csrf(original)})
        replay = copied.get("/admin")
        self.assertEqual(replay.status_code, 302)
        self.assertIn("/login", replay.headers["Location"])

    def test_security_headers_and_secure_cookie_mode(self):
        client = application.app.test_client()
        old_value = application.app.config["SESSION_COOKIE_SECURE"]
        application.app.config["SESSION_COOKIE_SECURE"] = True
        try:
            response = self.login(client)
        finally:
            application.app.config["SESSION_COOKIE_SECURE"] = old_value
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_members_can_manage_only_their_own_notes(self):
        owner = application.app.test_client()
        self.register(owner, "note-owner")
        self.login(owner, "note-owner", "a-secure-user-password")
        created = owner.post(
            "/notes",
            data={
                "content": "<script>alert('private')</script>\n내 메모",
                "csrf_token": self.csrf(owner),
            },
        )
        self.assertEqual(created.status_code, 302)
        self.assertTrue(created.headers["Location"].endswith("/#notes"))

        with application.app.app_context():
            note = application.get_db().execute(
                "SELECT notes.id FROM notes JOIN users ON users.id = notes.owner_id "
                "WHERE users.username = ?",
                ("note-owner",),
            ).fetchone()

        owner_page = owner.get("/").get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert", owner_page)
        self.assertNotIn("<script>alert", owner_page)

        other = application.app.test_client()
        self.register(other, "note-other")
        self.login(other, "note-other", "a-secure-user-password")
        self.assertNotIn("내 메모", other.get("/").get_data(as_text=True))
        other.post(
            f"/notes/{note['id']}/delete",
            data={"csrf_token": self.csrf(other)},
        )
        with application.app.app_context():
            self.assertIsNotNone(
                application.get_db().execute(
                    "SELECT id FROM notes WHERE id = ?", (note["id"],)
                ).fetchone()
            )

        owner.post(
            f"/notes/{note['id']}/delete",
            data={"csrf_token": self.csrf(owner)},
        )
        self.assertNotIn("내 메모", owner.get("/").get_data(as_text=True))

    def test_note_limits_and_authentication_are_enforced(self):
        visitor = application.app.test_client()
        denied = visitor.post(
            "/notes",
            data={"content": "visitor", "csrf_token": self.csrf(visitor)},
        )
        self.assertEqual(denied.status_code, 302)
        self.assertIn("/login", denied.headers["Location"])

        member = application.app.test_client()
        self.register(member, "limited-notes")
        self.login(member, "limited-notes", "a-secure-user-password")
        too_long = member.post(
            "/notes",
            data={"content": "x" * 1001, "csrf_token": self.csrf(member)},
        )
        self.assertEqual(too_long.status_code, 302)
        with application.app.app_context():
            count = application.get_db().execute(
                "SELECT COUNT(*) FROM notes JOIN users ON users.id = notes.owner_id "
                "WHERE users.username = ?",
                ("limited-notes",),
            ).fetchone()[0]
        self.assertEqual(count, 0)


class BootstrapMigrationTests(unittest.TestCase):
    def test_fresh_database_requires_strong_admin_password(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                application.initialize_database(Path(directory) / "fresh.db")

    def test_legacy_admin_is_never_promoted_by_username(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.db"
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, clicks INTEGER NOT NULL DEFAULT 0)")
                db.execute("INSERT INTO users (username, password_hash) VALUES ('admin', 'legacy-hash')")
                db.commit()
            with self.assertRaisesRegex(RuntimeError, "refusing automatic promotion"):
                application.initialize_database(database)
            with sqlite3.connect(database) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
                if "is_admin" in columns:
                    self.assertEqual(db.execute("SELECT is_admin FROM users WHERE username='admin'").fetchone()[0], 0)

    def test_verified_legacy_admin_can_be_migrated(self):
        from werkzeug.security import generate_password_hash
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.db"
            password = "verified-legacy-password"
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, clicks INTEGER NOT NULL DEFAULT 0)")
                db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", generate_password_hash(password)))
                db.commit()
            application.initialize_database(database, admin_password=password)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute("SELECT is_admin FROM users WHERE username='admin'").fetchone()[0], 1)

    def test_known_legacy_default_password_requires_rotation(self):
        from werkzeug.security import check_password_hash, generate_password_hash
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy-default.db"
            old_password = "admin" + "1234"
            with sqlite3.connect(database) as db:
                db.execute(
                    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, "
                    "password_hash TEXT NOT NULL, clicks INTEGER NOT NULL DEFAULT 0, "
                    "is_admin INTEGER NOT NULL DEFAULT 0)"
                )
                db.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                    ("admin", generate_password_hash(old_password)),
                )
                db.commit()
            with self.assertRaisesRegex(RuntimeError, "must be rotated"):
                application.initialize_database(database)
            new_password = "rotated-secure-admin-password"
            application.initialize_database(database, admin_password=new_password)
            with sqlite3.connect(database) as db:
                password_hash = db.execute(
                    "SELECT password_hash FROM users WHERE username='admin'"
                ).fetchone()[0]
            self.assertFalse(check_password_hash(password_hash, old_password))
            self.assertTrue(check_password_hash(password_hash, new_password))


if __name__ == "__main__":
    unittest.main()
