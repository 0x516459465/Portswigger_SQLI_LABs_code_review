# PortSwigger SQL Injection Labs — Local Docker Recreations

Self-contained Docker recreations of every **SQL injection** lab from the
[PortSwigger Web Security Academy](https://portswigger.net/web-security/sql-injection).
Each lab is a standalone Django application pinned to a loopback-only port,
seeded with its own data, and carrying a `FLAG{...}` that is only reachable
through the intended exploit chain.

> **⚠️ Intentionally vulnerable software.**
> These applications concatenate user input into SQL, reflect database errors,
> and skip input validation **on purpose**. Run them only in an isolated
> container on `127.0.0.1`. Never expose them to a network.

---

## Repository layout

```
.
├── psw-sqli-01-hidden-data/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── WRITEUP.md            ← full solution + mitigation notes
│   ├── shop/                 ← Django app (vulnerable code lives here)
│   └── sqli_lab/             ← Django project
├── psw-sqli-02-login-bypass/
│   └── ...
├── ...
└── psw-sqli-18-filter-bypass-xml-encoding/
```

Every lab follows the same skeleton so switching between them is friction-free.
The vulnerability always lives in `shop/views.py`; the seed data (including the
flag row) lives in `shop/management/commands/seed.py`.

---

## Lab index

| #  | Lab                                                      | Port   | Backend        | PortSwigger | Writeup |
|----|----------------------------------------------------------|--------|----------------|-------------|---------|
| 01 | SQLi in WHERE clause – retrieve hidden data              | 18001  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data) | [writeup](psw-sqli-01-hidden-data/WRITEUP.md) |
| 02 | SQLi allowing login bypass                               | 18002  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/lab-login-bypass) | [writeup](psw-sqli-02-login-bypass/WRITEUP.md) |
| 03 | SQLi – query database version (Oracle)                   | 18003  | Oracle Free 23 | [link](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) | [writeup](psw-sqli-03-oracle-version/WRITEUP.md) |
| 04 | SQLi – query database version (MySQL/MSSQL)              | 18004  | MySQL 8.4      | [link](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft) | [writeup](psw-sqli-04-mysql-mssql-version/WRITEUP.md) |
| 05 | SQLi – listing database contents (non-Oracle)            | 18005  | MySQL 8.4      | [link](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle) | [writeup](psw-sqli-05-list-db-contents-non-oracle/WRITEUP.md) |
| 06 | SQLi – listing database contents (Oracle)                | 18006  | Oracle Free 23 | [link](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle) | [writeup](psw-sqli-06-list-db-contents-oracle/WRITEUP.md) |
| 07 | UNION attack – determining column count                  | 18007  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) | [writeup](psw-sqli-07-union-column-count/WRITEUP.md) |
| 08 | UNION attack – finding a column containing text          | 18008  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) | [writeup](psw-sqli-08-find-text-column/WRITEUP.md) |
| 09 | UNION attack – retrieving data from other tables         | 18009  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables) | [writeup](psw-sqli-09-union-retrieve-data/WRITEUP.md) |
| 10 | UNION attack – retrieving multiple values in a column    | 18010  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column) | [writeup](psw-sqli-10-union-single-column/WRITEUP.md) |
| 11 | Blind SQLi – conditional responses                       | 18011  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) | [writeup](psw-sqli-11-blind-conditional-responses/WRITEUP.md) |
| 12 | Blind SQLi – conditional errors                          | 18012  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors) | [writeup](psw-sqli-12-blind-conditional-errors/WRITEUP.md) |
| 13 | Visible error-based SQLi                                 | 18013  | PostgreSQL 16  | [link](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based) | [writeup](psw-sqli-13-visible-error-based/WRITEUP.md) |
| 14 | Blind SQLi – time delays                                 | 18014  | PostgreSQL 16  | [link](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays) | [writeup](psw-sqli-14-time-delays/WRITEUP.md) |
| 15 | Blind SQLi – time delays and information retrieval       | 18015  | PostgreSQL 16  | [link](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval) | [writeup](psw-sqli-15-time-delays-info-retrieval/WRITEUP.md) |
| 16 | Blind SQLi – out-of-band interaction                     | 18016  | PostgreSQL 16 + OOB recorder | [link](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band) | [writeup](psw-sqli-16-out-of-band/WRITEUP.md) |
| 17 | Blind SQLi – out-of-band data exfiltration               | 18017  | PostgreSQL 16 + OOB recorder | [link](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration) | [writeup](psw-sqli-17-out-of-band-data-exfiltration/WRITEUP.md) |
| 18 | SQLi with filter bypass via XML encoding                 | 18018  | SQLite         | [link](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) | [writeup](psw-sqli-18-filter-bypass-xml-encoding/WRITEUP.md) |

Every host port is bound to `127.0.0.1` only — labs are not reachable from
other machines on the network unless you change the binding yourself.

---

## Quick start

**Requirements:** Docker Engine ≥ 24 with the `docker compose` plugin.
~4 GB of free disk (Oracle images are large; Postgres images are small).

```bash
# Pick any lab
cd psw-sqli-01-hidden-data

# Build + run
docker compose up --build

# In another terminal, hit the app
curl http://127.0.0.1:18001/

# Tear it down
docker compose down -v
```

Lab 01 comes up in a few seconds. Labs that boot a real Oracle Free instance
(03, 06) take 1–3 minutes on first run while the image initialises.

### Running the OOB labs (16, 17)

Labs 16 and 17 ship with a third service — `oob` — that records inbound
connections on an in-container hostname. You don't need to touch any
Burp Collaborator equivalent; the lab is entirely self-hosted. See the
lab's `WRITEUP.md` for the payload shape.

---

## Anatomy of a lab

Taking `psw-sqli-01-hidden-data` as the canonical example:

| File                                              | What it is                                    |
|---------------------------------------------------|-----------------------------------------------|
| `docker-compose.yml`                              | 1–3 services, fixed port, private network     |
| `Dockerfile`                                      | Python 3.12-slim + Django                     |
| `entrypoint.sh`                                   | Runs migrations + seed, starts gunicorn       |
| `manage.py`, `sqli_lab/`                          | Standard Django project                       |
| `shop/views.py`                                   | **The vulnerable endpoint**                   |
| `shop/models.py`                                  | ORM models                                    |
| `shop/management/commands/seed.py`                | Seeds products, users, and the `FLAG{...}`    |
| `shop/templates/shop/*.html`                      | Minimal UI                                    |
| `WRITEUP.md`                                      | Exploit walkthrough + code/network mitigation |

---

## Solving the labs

Each lab has its own [`WRITEUP.md`](psw-sqli-01-hidden-data/WRITEUP.md)
with:

1. **Lab overview** — topic, CWE, backend, host URL, flag.
2. **Exploit walkthrough** — raw HTTP requests and the resulting SQL.
3. **Vulnerable code** — annotated snippets of the real `views.py` with
   line-linked references.
4. **Why the vulnerability exists** — root-cause table.
5. **Code-level mitigation** — parameterisation, ORM, validation, schema
   gates, and so on.
6. **Network / infrastructure-level mitigation** — WAF, least-privilege DB
   accounts, network segmentation, egress control, monitoring.
7. **Defense-in-depth checklist**.
8. **References** — PortSwigger, OWASP, CWE, framework docs.

If you want to solve the labs yourself without spoilers, don't open the
writeups — the flag is printed inside them.

---

## Security notes

- The apps intentionally ship SQL-injection sinks, echo SQL errors, and
  disable CSRF on specific endpoints. Do **not** treat any code in this
  repository as an example to copy.
- Seed scripts generate passwords with `secrets.token_urlsafe(...)` where
  applicable, so two installs of the same lab have different admin
  credentials. The flag is always static.
- No secrets, API keys, or third-party credentials are committed.
- Every Compose file binds to `127.0.0.1:*` by design. Review the binding
  before changing it.

---

## Contributing

If you spot a bug in the lab harness (not in the intentionally vulnerable
code), open an issue or PR. Please do not file issues for the SQL
injection flaws themselves — those are the point.

---

## License

[MIT](LICENSE). See the additional safety notice in the LICENSE file.

---

## References

- PortSwigger Web Security Academy — <https://portswigger.net/web-security>
- OWASP SQL Injection Prevention Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
