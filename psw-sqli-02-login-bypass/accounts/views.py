"""
Authentication views.

`login_view` is the vulnerable entry point modelled on the PortSwigger
lab "SQL injection vulnerability allowing login bypass". It builds the
credential lookup query by string concatenation and executes it as raw
SQL, which is exactly the shape the lab wants you to exploit.

The other views (home, my_account, logout) are ordinary session
plumbing that lets a successful login persist across requests so you
can verify which account the server thinks you are.
"""

import re

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import User


FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def _flag_for(user: User | None) -> str | None:
    if user is None:
        return None
    for attr in ("email", "username", "password"):
        value = getattr(user, attr, "")
        if isinstance(value, str):
            match = FLAG_RE.search(value)
            if match:
                return match.group(0)
    return None


def _current_user(request: HttpRequest) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


def home(request: HttpRequest) -> HttpResponse:
    return render(request, "accounts/home.html", {"user": _current_user(request)})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        return render(request, "accounts/login.html", {})

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")

    query = (
        "SELECT id, username, is_admin "
        "FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )

    error = None
    matched_user_id = None
    matched_username = None

    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()
    except Exception as exc:
        row = None
        error = f"Database error: {exc}"

    if row is not None:
        matched_user_id, matched_username, _is_admin = row
        request.session["user_id"] = matched_user_id
        return redirect("my_account")

    return render(
        request,
        "accounts/login.html",
        {
            "executed_sql": query,
            "error": error or "Invalid username or password.",
        },
    )


def logout_view(request: HttpRequest) -> HttpResponse:
    request.session.flush()
    return redirect("home")


def my_account(request: HttpRequest) -> HttpResponse:
    user = _current_user(request)
    if user is None:
        return redirect("login")
    flag = _flag_for(user)
    return render(
        request,
        "accounts/my_account.html",
        {"user": user, "solved": flag is not None, "flag": flag},
    )
