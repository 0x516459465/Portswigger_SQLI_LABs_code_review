"""
Storefront views (MySQL backend).

`filter_products` is the vulnerable entry point modelled on the
PortSwigger lab "SQL injection attack, querying the database type and
version on MySQL and Microsoft". The category query parameter is
concatenated straight into raw SQL, so an attacker can append a UNION
SELECT that pulls `@@version` into one of the returned columns.

The solve detector scans rendered rows for any substring that looks
like a MySQL / MariaDB / Microsoft SQL Server banner. When one shows
up, the page marks the lab solved.

Note: MySQL's inline comment token is `-- ` (dash-dash-space) or `#`.
On the wire this means URL-encoding a trailing space or substituting
`%23` for `#` in your payload.
"""

import re

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Product


FLAG_RE = re.compile(r"FLAG\{[^}]+\}")
DBMS_BANNER_RE = re.compile(
    r"(MySQL|MariaDB|Microsoft\s+SQL\s+Server|^\d+\.\d+\.\d+)",
    re.IGNORECASE,
)


def _first_flag(rows: list[dict]) -> str | None:
    for row in rows:
        for value in row.values():
            if isinstance(value, str):
                match = FLAG_RE.search(value)
                if match:
                    return match.group(0)
    return None


def _contains_dbms_banner(rows: list[dict]) -> bool:
    for row in rows:
        for value in row.values():
            if isinstance(value, str) and DBMS_BANNER_RE.search(value):
                return True
    return False


def home(request: HttpRequest) -> HttpResponse:
    categories = (
        Product.objects.filter(released=True)
        .values_list("category", flat=True)
        .distinct()
        .order_by("category")
    )
    featured = Product.objects.filter(released=True).order_by("id")[:6]
    return render(
        request,
        "shop/home.html",
        {"categories": list(categories), "featured": featured},
    )


def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, name, category, description, price, released "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )

    error = None
    rows: list[dict] = []

    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0].lower() for col in cursor.description]
            for row in cursor.fetchall():
                rows.append(dict(zip(columns, row)))
    except Exception as exc:
        error = f"Database error: {exc}"

    flag = _first_flag(rows)
    banner_seen = _contains_dbms_banner(rows)

    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "rows": rows,
            "executed_sql": query,
            "error": error,
            "solved": flag is not None,
            "flag": flag,
            "banner_seen": banner_seen,
        },
    )
