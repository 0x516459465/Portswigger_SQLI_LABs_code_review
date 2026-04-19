"""
Views for the "SQLi with filter bypass via XML encoding" lab.

Three surfaces:

1. `home` lists the catalog and hosts the client-side stock-check
   widget. No injection here - it just renders products.

2. `stock_check` is the vulnerable endpoint. It expects an XML POST
   of the form

       <stockCheck>
           <productId>1</productId>
           <storeId>1</storeId>
       </stockCheck>

   A raw-bytes blocklist filter runs first and rejects the request
   with HTTP 403 if any of SELECT, UNION, FROM, or WHERE appear in
   the request body (case-insensitive). Only if the filter passes
   does the XML parser run. The parser decodes numeric character
   references as part of ordinary XML parsing, so an attacker who
   encodes any single character of a blocked keyword
   (e.g. `&#x55;NION`) slips the keyword past the filter - the raw
   bytes do not contain the literal string "UNION" but the decoded
   text does. The extracted productId is then concatenated directly
   into `SELECT count FROM stock WHERE product_id = <productId>`.
   The first column of the first row is reflected in the response,
   which is what makes in-band UNION extraction possible.

   Intended payload (productId body after XML-decoding):

       0 UNION SELECT password FROM users WHERE username='administrator'

   Wire it up with at least one character of each keyword encoded,
   e.g.

       0 &#x55;NION &#x53;ELECT password &#x46;ROM users
       &#x57;HERE username='administrator'

3. `login_view` + `my_account`: parameterized, safe. Log in as
   administrator with the password recovered through the stock
   check to reveal the flag.
"""

import xml.etree.ElementTree as ET

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Flag, Product, User


BLOCKED_KEYWORDS = (b"SELECT", b"UNION", b"FROM", b"WHERE")
MAX_BODY_BYTES = 16 * 1024


def _current_user(request: HttpRequest) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


def _contains_blocked_keyword(body: bytes) -> str | None:
    upper = body.upper()
    for keyword in BLOCKED_KEYWORDS:
        if keyword in upper:
            return keyword.decode()
    return None


def home(request: HttpRequest) -> HttpResponse:
    products = list(Product.objects.order_by("id"))
    return render(
        request,
        "shop/home.html",
        {
            "products": products,
            "current_user": _current_user(request),
        },
    )


@csrf_exempt
@require_http_methods(["POST"])
def stock_check(request: HttpRequest) -> HttpResponse:
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

    # XML parsing happens after the filter. The parser decodes
    # numeric character references, so encoded keywords survive the
    # filter and then decode back to plain text here.
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        return HttpResponse(
            f"Invalid XML: {exc}",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

    product_id = (root.findtext("productId") or "").strip()
    if not product_id:
        return HttpResponse(
            "Missing <productId>.",
            status=400,
            content_type="text/plain; charset=utf-8",
        )

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
    except Exception as exc:
        return HttpResponse(
            f"Database error: {exc}",
            status=500,
            content_type="text/plain; charset=utf-8",
        )

    if row is None:
        return HttpResponse(
            "Out of stock.",
            content_type="text/plain; charset=utf-8",
        )

    # Reflect the first column verbatim: the attacker's UNION rides
    # back out through this single field.
    return HttpResponse(
        str(row[0]),
        content_type="text/plain; charset=utf-8",
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        return render(request, "shop/login.html", {})

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    # Safe parameterized lookup - only real credentials get through.
    user = User.objects.filter(username=username, password=password).first()
    if user is None:
        return render(
            request,
            "shop/login.html",
            {"error": "Invalid username or password."},
        )

    request.session["user_id"] = user.id
    return redirect("my_account")


def logout_view(request: HttpRequest) -> HttpResponse:
    request.session.flush()
    return redirect("home")


def my_account(request: HttpRequest) -> HttpResponse:
    user = _current_user(request)
    if user is None:
        return redirect("login")

    flag = None
    if user.is_admin:
        flag_row = Flag.objects.first()
        if flag_row is not None:
            flag = flag_row.content

    return render(
        request,
        "shop/my_account.html",
        {"user": user, "solved": flag is not None, "flag": flag},
    )
