"""Local coursework login server. Run: py app.py"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from http.cookies import SimpleCookie
import hashlib
import json
import secrets
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / 'users.db'
SESSIONS = {}


def open_database():
    # mode=rw refuses to silently create an empty database at the wrong path.
    return sqlite3.connect(DATABASE.as_uri() + '?mode=rw', uri=True)


def initialize():
    if DATABASE.exists():
        raise SystemExit('users.db already exists; it has NOT been changed.')
    with sqlite3.connect(DATABASE) as db:
        db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, '
                   'username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
        for username, password in [('student', 'Test1234!'), ('admin', 'Admin1234!')]:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                       (username, hashlib.sha256(password.encode()).hexdigest()))
    print('Created', DATABASE)


def authenticate(username, password):
    # INTENTIONALLY UNSAFE: local SQL-injection coursework demonstration only.
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    query = (f"SELECT username FROM users WHERE username = '{username}' "
             f"AND password_hash = '{password_hash}'")
    with open_database() as db:
        row = db.execute(query).fetchone()
    return row[0] if row else None


class Handler(BaseHTTPRequestHandler):
    def send(self, status, content, content_type='text/html; charset=utf-8', cookie=None):
        body = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status, message, cookie=None):
        self.send(status, json.dumps({'message': message}), 'application/json', cookie)

    def current_user(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            token = cookie.get('session')
            session = SESSIONS.get(token.value) if token else None
            if session and session[1] > time.time():
                return session[0]
        except Exception:
            pass
        return None

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/':
            self.send(200, (ROOT / 'login.html').read_text(encoding='utf-8').replace('<h2>Login</h2>', '<h2>Login — vulnerable lab</h2>'))
        elif path == '/script.js':
            self.send(200, (ROOT / 'script.js').read_text(encoding='utf-8'), 'text/javascript')
        elif path == '/welcome':
            if not self.current_user():
                self.send(401, '<h1>Please log in first</h1><a href="/">Back to login</a>')
            else:
                self.send(200, '<h1>Successfully logged in!</h1><p>You reached a protected page.</p>'
                          '<button onclick="fetch(\'/logout\',{method:\'POST\'}).then(()=>location.href=\'/\')">Log out</button>')
        else:
            self.send(404, 'Not found', 'text/plain')

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == '/logout':
            cookie = SimpleCookie()
            cookie.load(self.headers.get('Cookie', ''))
            if cookie.get('session'):
                SESSIONS.pop(cookie['session'].value, None)
            self.json_response(200, 'Logged out', 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            return
        if path != '/login':
            self.json_response(404, 'Not found')
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 4096:
                raise ValueError()
            data = json.loads(self.rfile.read(length))
            username, password = data['username'], data['password']
            if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            self.json_response(400, 'Please fill in both fields.')
            return
        try:
            user = authenticate(username, password)
        except sqlite3.Error:
            self.json_response(500, 'Database unavailable. Check users.db and its users table.')
            return
        if not user:
            self.json_response(401, 'Incorrect username or password.')
            return
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = (user, time.time() + 3600)
        self.json_response(200, 'Successfully logged in!',
                           f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600')


if __name__ == '__main__':
    if '--init' in sys.argv:
        initialize()
    else:
        with open_database() as db:
            db.execute('SELECT id, username, password_hash FROM users LIMIT 1')
        print('Database:', DATABASE)
        print('Open http://127.0.0.1:5000 in this computer\'s browser. Ctrl+C stops the server.')
        ThreadingHTTPServer(('127.0.0.1', 5000), Handler).serve_forever()
