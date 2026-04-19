"""
Views for the "UNION attack - determine number of columns" SQLi lab.

`filter_products` concatenates the `category` query parameter straight
into raw SQL. The SELECT list is 5 columns wide:

    SELECT id, name, category, description, price
    FROM products
    WHERE category = '<user>' AND released = 1

Two intended solves:

1. ORDER BY probing:    ?category=Gifts' ORDER BY 1-- ... up to 6
   A request at position 6 errors because the SELECT only has 5
   columns - the error is rendered, giving the attacker the count.

2. UNION SELECT NULL probing: ?category=Gifts' UNION SELECT NULL-- ...
   Only the 5-NULL variant executes cleanly and returns an extra row
   whose every column is NULL. That row is the solve signal - the
   view detects an all-NULL row and reveals the flag.

Making the flag surface only on a *successful* UNION means a learner
cannot accidentally solve the lab by spraying random payloads; they
have to get the column count right.
"""

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


FLAG_CONTENT = "FLAG{psw-sqli-07-union-column-count-5}"


def _has_all_null_row(rows: list[tuple]) -> bool:
    # A row composed entirely of NULLs can only exist in the result
    # set via UNION SELECT NULL,NULL,... with a column count matching
    # the base query. Real product rows always have non-null id/name.
    for row in rows:
        if len(row) > 0 and all(value is None for value in row):
            return True
    return False


def home(request: HttpRequest) -> HttpResponse:
    from .models import Product

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

    # Deliberately 5-column SELECT list (no `released`) so the column
    # count is not trivially derivable from the Product model.
    query = (
        "SELECT id, name, category, description, price "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )

    error = None
    rows: list[tuple] = []
    columns: list[str] = []

    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [col[0] for col in cursor.description]
            rows = cursor.fetchall()
    except Exception as exc:
        error = f"Database error: {exc}"

    solved = _has_all_null_row(rows)

    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "columns": columns,
            "rows": rows,
            "executed_sql": query,
            "error": error,
            "solved": solved,
            "flag": FLAG_CONTENT if solved else None,
        },
    )
