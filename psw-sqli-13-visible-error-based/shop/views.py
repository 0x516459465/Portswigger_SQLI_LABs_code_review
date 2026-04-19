"""
Views for the "SQL injection with visible error-based data exfiltration"
lab.

Three surfaces:

1. `home` is the vulnerable entry point. The `TrackingId` cookie is
   spliced directly into a raw SQL query against `tracked_users`:

       SELECT tracking_id FROM tracked_users WHERE tracking_id = '<cookie>'

   The query result is never rendered. When the query raises an
   exception, however, the full database error message is reflected
   back into the home page. PostgreSQL's CAST errors embed the
   offending operand value - so a payload like

       ' AND 1=CAST((SELECT password FROM users WHERE
         username='administrator') AS INT)--

   produces an error message of the form

       invalid input syntax for type integer: "h3pl4y3r..."

   ...leaking the admin password in a single request.

2. `login_view` is parameterized and safe - the attacker must recover
   real credentials through the visible-error side channel.

3. `my_account` reveals the flag when the authenticated user is
   flagged as `is_admin` in the `users` table.
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

    # Vulnerable lookup. Cookie is concatenated directly into SQL.
    # On DB exception, the full driver error text (which on PostgreSQL
    # embeds operand values from failed casts) is rendered verbatim
    # into the response body - that is the visible side channel.
    error_message = None
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception as exc:
            error_message = str(exc)

    response = render(
        request,
        "shop/home.html",
        {
            "current_user": _current_user(request),
            "error_message": error_message,
        },
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

    # Safe parameterized lookup - the attacker cannot bypass this and
    # must recover real credentials via the visible-error channel.
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
