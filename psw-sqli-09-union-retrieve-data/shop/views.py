"""
Views for the "UNION attack - retrieve data from other tables" lab.

Two surfaces:

1. `filter_products` is the vulnerable entry point: the `category`
   query parameter is concatenated into raw SQL that projects 2 text
   columns. The attacker pivots this into
   `UNION SELECT username, password FROM users-- ` to extract creds.

2. `login_view` is intentionally *safe* (parameterized) because the
   teaching goal is to log in with credentials obtained from the
   UNION chain. Making login injectable would skip the extraction.

The my-account page reveals the flag only when the current session is
bound to an administrator account.
"""

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Flag, Product, User


def _current_user(request: HttpRequest) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


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
            "current_user": _current_user(request),
        },
    )


def filter_products(request: HttpRequest) -> HttpResponse:
    category = request.GET.get("category", "")

    # Two-column SELECT list. Both columns are text-typed so the
    # attacker can UNION arbitrary string pairs into them.
    query = (
        "SELECT name, description "
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

    return render(
        request,
        "shop/filter.html",
        {
            "category": category,
            "rows": rows,
            "executed_sql": query,
            "error": error,
        },
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        return render(request, "shop/login.html", {})

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

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
