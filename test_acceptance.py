"""Run: py -m unittest -v test_acceptance.py. Uses a temporary database only."""
import http.cookiejar
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import app

VULNERABLE = True
PAYLOAD = "' OR '1'='1' --"

class AcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.original_database = app.DATABASE
        app.DATABASE = Path(cls.temporary.name) / 'users.db'
        app.initialize()
        cls.server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)
        app.DATABASE = cls.original_database
        cls.temporary.cleanup()

    def setUp(self):
        self.client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, data=None):
        request = urllib.request.Request(self.url + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Content-Type': 'application/json'})
        try:
            response = self.client.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode()

    def login(self, username, password):
        return self.request('/login', {'username': username, 'password': password})

    def test_01_page_and_script_load(self):
        self.assertEqual(self.request('/')[0], 200)
        self.assertEqual(self.request('/script.js')[0], 200)

    def test_02_correct_password_grants_protected_access(self):
        self.assertEqual(self.login('student', 'Test1234!')[0], 200)
        self.assertEqual(self.request('/welcome')[0], 200)

    def test_03_wrong_password_is_rejected(self):
        self.assertEqual(self.login('student', 'wrongpassword')[0], 401)
        self.assertEqual(self.request('/welcome')[0], 401)

    def test_04_exact_sql_injection(self):
        expected = 200 if VULNERABLE else 401
        self.assertEqual(self.login(PAYLOAD, 'wrongpassword')[0], expected)
        self.assertEqual(self.request('/welcome')[0], expected)

    def test_05_logout_revokes_access(self):
        self.assertEqual(self.login('student', 'Test1234!')[0], 200)
        self.assertEqual(self.request('/logout', {})[0], 200)
        self.assertEqual(self.request('/welcome')[0], 401)

    def test_06_database_file_not_served(self):
        self.assertEqual(self.request('/users.db')[0], 404)

    def test_07_database_integrity_and_accounts(self):
        with app.open_database() as database:
            self.assertEqual(database.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(database.execute('SELECT count(*) FROM users').fetchone()[0], 2)

    def test_08_empty_fields_rejected(self):
        self.assertEqual(self.login('', '')[0], 400)

if __name__ == '__main__':
    unittest.main()
