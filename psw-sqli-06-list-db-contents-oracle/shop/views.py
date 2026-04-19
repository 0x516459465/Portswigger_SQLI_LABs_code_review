"""
Views for the "list database contents on Oracle" SQLi lab.

Two surfaces:

1. `filter_products` is the vulnerable entry point: the `category`
   query parameter is concatenated straight into raw SQL executed
   against the Oracle backend. This is the pivot used to enumerate
   USER_TABLES / USER_TAB_COLUMNS and extract admin credentials.

2. `login_view` is intentionally *safe* (parameterized) because the
   lab's teaching goal is to recover real credentials via the UNION
   chain and then log in with them. Making the login view injectable
   would let the learner short-circuit past the enumeration step.

The my-account page only reveals the flag when the current session is
bound to an administrator account, so the full chain is:

    /filter?category=...   -> UNION SELECT ... FROM dual
    -> enumerate USER_TABLES / USER_TAB_COLUMNS
    -> read users.username / users.password
    -> /login with extracted credentials
    -> /my-account shows FLAG{...}

Oracle notes:
* Any UNION branch that does not reference a real table must end in
  `FROM dual` (Oracle has no implicit FROM clause).
* Under the `labuser` schema, USER_TABLES returns only the three lab
  tables (products / users / flags), which keeps the enumeration
  surface clean for learners.
"""

import re

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Flag, Product, User


FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def _lob_to_str(value):
    # oracledb returns NCLOB/CLOB columns as LOB objects by default.
    # Read them eagerly so template rendering and flag scanning see
    # a plain string.
    if hasattr(value, "read") and not isinstance(value, (str, bytes)):
        try:
            return value.read()
        except Exception:
            return str(value)
    return value


def _current_user(request: HttpRequest) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


def _first_flag(rows: list[dict]) -> str | None:
    for row in rows:
        for value in row.values():
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
        {
            "categories": list(categories),
            "featured": featured,
            "current_user": _current_user(request),
        },
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
                rows.append(
                    dict(zip(columns, (_lob_to_str(v) for v in row)))
                )
    except Exception as exc:
        error = f"Database error: {exc}"

    flag = _first_flag(rows)

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
