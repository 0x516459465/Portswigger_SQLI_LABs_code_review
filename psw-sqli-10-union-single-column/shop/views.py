"""
Views for the "UNION attack - retrieve multiple values in a single
column" SQLi lab.

Two surfaces:

1. `filter_products` is the vulnerable entry point. The base SELECT
   projects 2 columns but the template renders only column 2 as a
   product card. Column 1 is discarded.

2. `login_view` is parameterized and safe - the learner must log in
   with credentials obtained from the UNION chain.

The 2-column base query with only one rendered slot forces the
attacker to merge both pieces of data (username AND password) into
that single visible slot, typically with `||` string concatenation:

    ?category=Gifts' UNION SELECT NULL, username || ':' || password FROM users-- -

Each credential pair then surfaces as a "product" in the result list.
Log in as administrator and /my-account reveals the flag.
"""

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Flag, Product, User


TEXT_COLUMN_INDEX = 1  # only column 2 (index 1) is rendered in HTML


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

    # 2-column SELECT. Only column 2 (name) is rendered by the
    # template, so the attacker must funnel both username and password
    # through that single slot via string concatenation.
    query = (
        "SELECT id, name "
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
