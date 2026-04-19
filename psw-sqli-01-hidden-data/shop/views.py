"""
Storefront views.

The `filter_products` view is the vulnerable entry point modelled on the
PortSwigger lab "SQL injection vulnerability in WHERE clause allowing
retrieval of hidden data". The rest of the file is ordinary storefront
plumbing so the lab feels like a real application during code review.
"""

import re

from django.db import connection
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Product


FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def _first_flag(products: list[dict]) -> str | None:
    for p in products:
        for value in p.values():
            if isinstance(value, str):
                match = FLAG_RE.search(value)
                if match:
                    return match.group(0)
    return None


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

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()

    products = [
        {
            "id": row[0],
            "name": row[1],
            "category": row[2],
            "description": row[3],
            "price": row[4],
            "released": bool(row[5]),
        }
        for row in rows
    ]

    flag = _first_flag(products)

    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "products": products,
            "executed_sql": query,
            "solved": flag is not None,
            "flag": flag,
        },
    )


def product_detail(request: HttpRequest, product_id: int) -> HttpResponse:
    try:
        product = Product.objects.get(pk=product_id, released=True)
    except Product.DoesNotExist as exc:
        raise Http404("Product not available.") from exc
    return render(request, "shop/product.html", {"product": product})
