"""
Seed the conditional-errors blind-boolean lab.

Administrator password is drawn from a short lowercase alphabet so a
scripted conditional-error extractor (Burp Intruder with a grep-status
rule on HTTP 500) can realistically recover it one character at a time
through the SQL-error side channel.

The tracked_users table holds the cookie value baked into a fresh
browser session - so the legitimate request path always runs a
successful query and returns 200, matching real-world behaviour of the
tracking endpoint.

Run inside the container:

    python manage.py seed
"""

import secrets
import string

from django.core.management.base import BaseCommand

from shop.models import Flag, TrackedUser, User


SEEDED_TRACKING_ID = "psw-lab-visitor-001"

LOW_PRIV_USERS = [
    ("wiener", "peter"),
    ("carlos", "montoya"),
]

ADMIN_PASSWORD_LENGTH = 8
ADMIN_PASSWORD_ALPHABET = string.ascii_lowercase

FLAG_CONTENT = "FLAG{psw-sqli-12-blind-conditional-errors-admin-access}"


class Command(BaseCommand):
    help = "Populate tracked_users, users, and the flag table."

    def handle(self, *args, **options) -> None:
        TrackedUser.objects.all().delete()
        TrackedUser.objects.create(tracking_id=SEEDED_TRACKING_ID)

        User.objects.all().delete()
        admin_password = "".join(
            secrets.choice(ADMIN_PASSWORD_ALPHABET)
            for _ in range(ADMIN_PASSWORD_LENGTH)
        )
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
