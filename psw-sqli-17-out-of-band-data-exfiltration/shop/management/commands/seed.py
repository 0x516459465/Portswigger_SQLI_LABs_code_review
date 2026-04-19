"""
Seed the out-of-band data-exfiltration lab.

The administrator password is a random URL-safe token. Unlike the
time-based extraction lab, there is no iterative guessing: the
intended path exfiltrates the whole password in a single SQL
injection by embedding `(SELECT password FROM users WHERE
username='administrator')` into a libpq connection string that
`dblink_connect()` will send over TCP to the oob recorder.

URL-safe alphabet (base64url) matters because libpq's connection-
string parser would choke on spaces, quotes, or equals signs inside
a parameter value. `secrets.token_urlsafe` only produces
[A-Za-z0-9_-], which is safe.

Run inside the container:

    python manage.py seed
"""

import secrets

from django.core.management.base import BaseCommand

from shop.models import Flag, TrackedUser, User


SEEDED_TRACKING_ID = "psw-lab-visitor-001"

LOW_PRIV_USERS = [
    ("wiener", "peter"),
    ("carlos", "montoya"),
]

ADMIN_PASSWORD_BYTES = 12

FLAG_CONTENT = "FLAG{psw-sqli-17-out-of-band-exfiltration-admin-access}"


class Command(BaseCommand):
    help = "Populate tracked_users, users, and the flag table."

    def handle(self, *args, **options) -> None:
        TrackedUser.objects.all().delete()
        TrackedUser.objects.create(tracking_id=SEEDED_TRACKING_ID)

        User.objects.all().delete()
        admin_password = secrets.token_urlsafe(ADMIN_PASSWORD_BYTES)
        User.objects.create(
            username="administrator",
            password=admin_password,
            is_admin=True,
        )
        for username, password in LOW_PRIV_USERS:
            User.objects.create(
                username=username,
                password=password,
                is_admin=False,
            )

        Flag.objects.all().delete()
        Flag.objects.create(content=FLAG_CONTENT)

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded 1 tracked user, "
                f"{1 + len(LOW_PRIV_USERS)} users, 1 flag."
            )
        )
