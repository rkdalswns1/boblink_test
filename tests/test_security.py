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


class NotesApiTests(unittest.TestCase):
    setUp = AppSecurityTests.setUp
    csrf = AppSecurityTests.csrf
    login = AppSecurityTests.login

    def api_client(self, username="api-user"):
        with application.app.app_context():
            db = application.get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, application.generate_password_hash("1235678")),
            )
            db.commit()
        client = application.app.test_client()
        self.assertEqual(self.login(client, username, "1235678").status_code, 302)
        return client

    def api_post(self, client, payload):
        token = client.get("/api/csrf").get_json()["csrf_token"]
        return client.post("/api/notes", json=payload, headers={"X-CSRF-Token": token})

    def test_api_requires_session_before_validating_input(self):
        client = application.app.test_client()
        for method, path in [("GET", "/api/notes"), ("POST", "/api/notes"),
                             ("GET", "/api/notes/1"), ("GET", "/api/csrf"),
                             ("GET", "/api/missing")]:
            with self.subTest(method=method, path=path):
                response = client.open(path, method=method)
                self.assertEqual(response.status_code, 401)
                self.assertIsInstance(response.get_json()["error"], str)
                self.assertNotIn("Location", response.headers)
                self.assertIn("no-store", response.headers["Cache-Control"])

    def test_api_create_list_and_fetch(self):
        client = self.api_client()
        self.assertEqual(client.get("/api/notes").get_json(), {"notes": []})
        first = self.api_post(client, {"title": "  meeting \t", "body": "3pm\nroom 2"})
        self.assertEqual(first.status_code, 201)
        note = first.get_json()
        self.assertIsInstance(note["id"], int)
        for key in ("title", "body", "created_at", "updated_at"):
            self.assertIsInstance(note[key], str)
        self.assertEqual(note["title"], "meeting")
        self.assertEqual(note["body"], "3pm\nroom 2")
        self.assertEqual(note["created_at"], note["updated_at"])
        self.assertRegex(note["created_at"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        second = self.api_post(client, {"title": "empty body", "owner_id": 1}).get_json()
        self.assertEqual(second["body"], "")
        self.assertEqual(client.get("/api/notes").get_json()["notes"], [second, note])
        self.assertEqual(client.get(f"/api/notes/{note['id']}").get_json(), note)

    def test_api_ownership_and_not_found(self):
        owner = self.api_client("api-owner")
        note = self.api_post(owner, {"title": "private"}).get_json()
        other = self.api_client("api-other")
        self.assertEqual(other.get("/api/notes").get_json(), {"notes": []})
        for note_id in (note["id"], 99999, 2**100, "not-an-id", -1):
            response = other.get(f"/api/notes/{note_id}")
            self.assertEqual(response.status_code, 404)
            self.assertTrue(response.is_json)

    def test_api_rejects_invalid_titles_and_bodies(self):
        client = self.api_client()
        payloads = [{}, {"title": ""}, {"title": " \t\n\u3000"},
                    {"title": None}, {"title": 4}, {"title": []},
                    {"title": "a" * 201}, [], "text"]
        payloads += [{"title": "valid", "body": body} for body in (None, 4, [], "x" * 1001)]
        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.api_post(client, payload)
                self.assertEqual(response.status_code, 400)
                self.assertTrue(response.is_json)
        self.assertEqual(client.get("/api/notes").get_json(), {"notes": []})
        self.assertEqual(self.api_post(client, {"title": "a" * 200, "body": "x" * 1000}).status_code, 201)

    def test_api_csrf_and_json_errors(self):
        client = self.api_client()
        for headers in ({}, {"X-CSRF-Token": "wrong"}, {"X-CSRF-Token": "한글"}):
            response = client.post("/api/notes", json={"title": "test"}, headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.is_json)
        token = client.get("/api/csrf").get_json()["csrf_token"]
        for data, content_type, status in [("{", "application/json", 400),
                                          ("null", "application/json", 400),
                                          ('{"title":"hi"}', "text/plain", 415)]:
            response = client.post("/api/notes", data=data, content_type=content_type,
                                   headers={"X-CSRF-Token": token})
            self.assertEqual(response.status_code, status)
            self.assertTrue(response.is_json)
        response = client.put("/api/notes", headers={"X-CSRF-Token": token})
        self.assertEqual(response.status_code, 405)
        self.assertTrue(response.is_json)
        self.assertIn("Allow", response.headers)
        oversized = client.post("/api/notes", json={"title": "x" * 20000},
                                headers={"X-CSRF-Token": token})
        self.assertEqual(oversized.status_code, 413)
        self.assertTrue(oversized.is_json)

    def test_api_expired_and_revoked_sessions(self):
        client = self.api_client()
        with application.app.app_context():
            db = application.get_db()
            db.execute("UPDATE auth_sessions SET expires_at = 0")
            db.commit()
        self.assertEqual(client.get("/api/notes").status_code, 401)
        self.login(client, "api-user", "1235678")
        cookie_name = application.app.config["SESSION_COOKIE_NAME"]
        copied = application.app.test_client()
        copied.set_cookie(cookie_name, client.get_cookie(cookie_name).value)
        client.post("/logout", data={"csrf_token": self.csrf(client)})
        self.assertEqual(copied.get("/api/notes").status_code, 401)

    def test_api_capacity_and_legacy_html_notes(self):
        client = self.api_client()
        client.post("/notes", data={"content": "existing HTML note", "csrf_token": self.csrf(client)})
        note = client.get("/api/notes").get_json()["notes"][0]
        self.assertEqual(note["title"], "메모")
        self.assertEqual(note["body"], "existing HTML note")
        self.assertEqual(note["created_at"], note["updated_at"])
        with application.app.app_context():
            db = application.get_db()
            owner_id = db.execute("SELECT id FROM users WHERE username='api-user'").fetchone()[0]
            db.executemany("INSERT INTO notes (owner_id, content) VALUES (?, ?)",
                           [(owner_id, "existing") for _ in range(99)])
            db.commit()
        response = self.api_post(client, {"title": "over capacity"})
        self.assertEqual(response.status_code, 409)
        self.assertTrue(response.is_json)
        self.assertEqual(len(client.get("/api/notes").get_json()["notes"]), 100)

    def test_api_schema_migration_preserves_old_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            with sqlite3.connect(path) as db:
                db.executescript("""
                    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL, clicks INTEGER NOT NULL DEFAULT 0,
                        is_admin INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO users (id, username, password_hash) VALUES (1, 'legacy', 'unused');
                    CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
                        content TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
                    INSERT INTO notes VALUES (1, 1, 'keep this', '2026-09-16 00:00:00');
                """)
            application.initialize_database(path)
            application.initialize_database(path)
            with sqlite3.connect(path) as db:
                row = db.execute(f"SELECT {application.NOTE_FIELDS} FROM notes WHERE id=1").fetchone()
            self.assertEqual(row, (1, "메모", "keep this", "2026-09-16 00:00:00", "2026-09-16 00:00:00"))


if __name__ == "__main__":
    unittest.main()
