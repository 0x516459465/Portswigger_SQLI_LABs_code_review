"""
Views for the "Blind SQL injection with conditional responses" lab.

Three surfaces:

1. `home` is the vulnerable entry point. On every request it reads the
   `TrackingId` cookie and splices it directly into a raw SQL query
   against the `tracked_users` table:

       SELECT TrackingId FROM tracked_users WHERE TrackingId = '<cookie>'

   If the query returns at least one row the page renders a "Welcome
   back!" banner; otherwise no banner is shown. SQL errors are
   swallowed silently so malformed payloads produce exactly the same
   signal as "no matching row" - a clean boolean side channel.

2. `login_view` is parameterized and safe. The attacker has to recover
   the administrator password through the blind side channel before
   they can authenticate.

3. `my_account` reveals the flag when the authenticated user is flagged
   as `is_admin` in the `users` table.

Intended exploit: extract the administrator password one character at
a time with payloads like:

    TrackingId=x' UNION SELECT 'x' WHERE (SELECT SUBSTR(password,1,1)
        FROM users WHERE username='administrator')='a'-- -

...observing the presence or absence of "Welcome back!" in the
response to learn each character.
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

    # Vulnerable lookup. Cookie is concatenated directly into SQL, and
    # both "zero rows" and "SQL error" collapse into the same
    # boolean-false branch so only a successful match flips the banner.
    tracked = False
    if tracking_id is not None:
        query = (
            "SELECT TrackingId FROM tracked_users "
            "WHERE TrackingId = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                rows = cursor.fetchall()
                tracked = len(rows) > 0
        except Exception:
            tracked = False

    response = render(
        request,
        "shop/home.html",
        {
            "tracked": tracked,
            "current_user": _current_user(request),
        },
    )

    # On the very first visit, bake in the legitimate tracking cookie so
    # the "Welcome back!" banner works out of the box for a legitimate
    # browser session.
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

    # Safe parameterized lookup - the attacker cannot bypass this and
    # must recover real credentials through the blind side channel.
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
