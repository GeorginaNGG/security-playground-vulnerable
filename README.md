# Security Playground vulnerable

Intentionally vulnerable SQL injection lab. This repository records the vulnerable stage of the coursework project.
The original frontend repository is https://github.com/GeorginaNGG/security-playground.

## Run in the Windows VM

Python 3.10 or newer is required; no extra packages are needed.

1. Download or clone this repository into its own folder.
2. In Command Prompt, change to that folder.
3. Run `py app.py --init` once to create a fresh local test database.
   It refuses to overwrite an existing `users.db`.
4. Run `py app.py` or double-click `START_LOGIN.bat`.
5. Open http://127.0.0.1:5000 inside that VM.

The server binds only to 127.0.0.1. Stop it before running the other version.
To reuse the VM's existing database instead of initializing a new one, copy
that `users.db` beside `app.py`. Database files are excluded from Git.

## Acceptance comparison

Log out before each attempt, and use a fresh login session for each test.

| Username | Password | Expected result in this version |
|---|---|---|
| `student` | `Test1234!` | Login succeeds and protected page opens |
| `student` | `wrongpassword` | Login is rejected |
| `' OR '1'='1' --` | `wrongpassword` | Login succeeds through the deliberate vulnerability |

The password in the injection test is deliberately the same wrong password
as in the negative control. Only the username changes.

## How this version works

The authenticate function deliberately builds SQL by placing the username directly inside the query string. The payload makes the WHERE condition true and comments out the password check. This version is intentionally unsafe and is only for a local, authorized lab demonstration.

The password is hashed before comparison to match the existing coursework
SQLite schema. SHA-256 alone is not appropriate password storage for a real
service. The fixed variant addresses SQL injection; this small HTTP lab is
not a production authentication system.

## Repeatable tests

Run:

```bat
py -m unittest -v test_acceptance.py
```

The eight tests use a temporary database and an unused loopback port. They
check page loading, correct and incorrect passwords, the exact injection,
logout, protected access, database integrity, and file exposure. In this
vulnerable version, the injection test passes when the attempt is
accepted (the intended demonstration).

A passing automated test is separate from evidence of a manual VM browser test.

## Files

- `app.py`: Python server and database query.
- `login.html`: HTML and CSS.
- `script.js`: sends the form to the server.
- `START_LOGIN.bat`: Windows startup script.
- `test_acceptance.py`: repeatable HTTP acceptance tests.
