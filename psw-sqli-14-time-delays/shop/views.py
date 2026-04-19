"""
View for the "Blind SQL injection with time delays" lab.

One surface:

`home` is the vulnerable entry point. The `TrackingId` cookie is
concatenated directly into the raw SQL query against `tracked_users`.
The query result is never reflected, and any database exception is
swallowed silently - so the response body is byte-identical whether
the injection is syntactically valid or not.

The view times the vulnerable query server-side and only releases the
flag when the query took at least ten seconds of wall time. That makes
a legitimate time-based SQLi the only path to the solve: the attacker
has to induce a delay inside the DB itself (e.g. PostgreSQL's
`pg_sleep(10)`), not just sit on a slow network link.

Intended exploit (PostgreSQL):

    TrackingId=x'||pg_sleep(10)-- -

`pg_sleep(10)` returns `void`; the `||` concatenation against `void`
ultimately raises an error, but only *after* the sleep executes, so
the wall-clock delay is still observed by the server and the flag is
released.
"""

import time

from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Flag


SEEDED_TRACKING_ID = "psw-lab-visitor-001"
SOLVE_THRESHOLD_SECONDS = 10.0


def home(request: HttpRequest) -> HttpResponse:
    tracking_id = request.COOKIES.get("TrackingId")

    # Vulnerable lookup. Cookie goes straight into the SQL string. The
    # query result is never read back out; errors are swallowed. The
    # only observable server-side effect under attack is wall-clock
    # time.
    duration = 0.0
    if tracking_id is not None:
        query = (
            "SELECT tracking_id FROM tracked_users "
            "WHERE tracking_id = '" + tracking_id + "'"
        )
        start = time.monotonic()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)
                cursor.fetchall()
        except Exception:
            pass
        duration = time.monotonic() - start

    solved = duration >= SOLVE_THRESHOLD_SECONDS
    flag = None
    if solved:
        flag_row = Flag.objects.first()
        if flag_row is not None:
            flag = flag_row.content

    response = render(
        request,
        "shop/home.html",
        {
            "duration": round(duration, 2),
            "threshold": int(SOLVE_THRESHOLD_SECONDS),
            "solved": solved,
            "flag": flag,
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
