"""
Views for the "UNION attack - find column containing text" SQLi lab.

The base query projects 3 columns in this order:

    SELECT id, price, name FROM products WHERE category = '<user>' AND released = 1

Only the third column (`name`) is rendered as a visible product card
on the filter page. The first two positions are dropped by the
template. This models the PortSwigger lab premise: one column of the
result set displays as text in the UI, and the attacker must discover
which one.

Solve condition: the challenge token (surfaced on the home page)
appears inside the `name`-position value of at least one row. A row
reaches the `name` position only if the attacker crafted a UNION that
places the token there, e.g.

    ?category=Gifts' UNION SELECT NULL,NULL,'<TOKEN>'--

Placing the token in positions 1 or 2 will not match because those
values are discarded by the template, and the server-side solve check
only looks at position 3.
"""

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Challenge, Product


TEXT_COLUMN_INDEX = 2  # position of `name` in the SELECT list


def _get_challenge() -> Challenge | None:
    return Challenge.objects.first()


def home(request: HttpRequest) -> HttpResponse:
    categories = (
        Product.objects.filter(released=True)
        .values_list("category", flat=True)
        .distinct()
        .order_by("category")
    )
    return render(
        request,
        "shop/home.html",
        {
            "categories": list(categories),
            "challenge": _get_challenge(),
        },
    )


def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    query = (
        "SELECT id, price, name "
        "FROM products "
        "WHERE category = '" + category + "' AND released = 1"
    )

    error = None
    rows: list[tuple] = []

    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            rows = cursor.fetchall()
    except Exception as exc:
        error = f"Database error: {exc}"

    # Only values that land in the text-rendered position count as a
    # solve - this is what distinguishes the lesson from "any column
    # will do".
    challenge = _get_challenge()
    solved = False
    if challenge is not None:
        token = challenge.token
        for row in rows:
            if len(row) > TEXT_COLUMN_INDEX:
                cell = row[TEXT_COLUMN_INDEX]
                if isinstance(cell, str) and token in cell:
                    solved = True
                    break

    displayed_names = [
        row[TEXT_COLUMN_INDEX] if len(row) > TEXT_COLUMN_INDEX else None
        for row in rows
    ]

    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "displayed_names": displayed_names,
            "row_count": len(rows),
            "executed_sql": query,
            "error": error,
            "solved": solved,
            "flag": challenge.flag if (solved and challenge) else None,
            "challenge": challenge,
        },
    )
