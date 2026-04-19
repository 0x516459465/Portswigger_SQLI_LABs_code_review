"""
Views for the "blind SQLi - time delays with information retrieval" lab.

Three surfaces:

1. `home` is the vulnerable entry point. The `TrackingId` cookie is
   concatenated directly into the raw SQL query against `tracked_users`.
   The query result is never reflected and all exceptions are swallowed
   silently, so the response body and status are identical regardless
   of what the payload does. The only observable side channel is how
   long the request takes to return - the attacker must craft a payload
   that conditionally blocks inside the database itself.

2. `login_view` is parameterized and safe. The attacker has to recover
   the administrator password through the timing side channel before
   they can authenticate.

3. `my_account` reveals the flag when the authenticated user is flagged
   as `is_admin`.

Intended exploit (PostgreSQL): chain `pg_sleep()` into a `CASE`
predicated on the administrator password, one character at a time:

    TrackingId=x'||(SELECT CASE WHEN (SUBSTR((SELECT password FROM users
        WHERE username='administrator'),1,1)='a')
        THEN pg_sleep(5) ELSE pg_sleep(0) END)::text||'

A response time >= ~5s means the guessed character is correct. Iterate
position x alphabet in Burp Intruder with a response-time grep column.
"""

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Flag, User


SEEDED_TRACKING_ID = "psw-lab-visitor-001"


def _current_user(request: HttpRequest) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return User.objects.filter(pk=user_id).first()


def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. Cookie goes straight into the SQL string. The
    # query result is never read back; errors are swallowed. The only
    # observable effect under attack is wall-clock delay.
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            pass

    response = render(
        request,
        "shop/home.html",
        {"current_user": _current_user(request)},
    )

    if tracking_id is None:
        response.set_cookie(
            "TrackingId",
            SEEDED_TRACKING_ID,
            max_age=60 * 60 * 24 * 365,
            httponly=False,
            samesite="Lax",
        )

    return response


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
