"""
Seed the visible-error-based SQLi lab.

Administrator password is a random 16-byte token. Unlike the
conditional-response / conditional-error variants, error-based
extraction leaks the full value in a single response, so no
small-charset brute is required - the password can be any shape.

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

FLAG_CONTENT = "FLAG{psw-sqli-13-visible-error-based-admin-access}"


class Command(BaseCommand):
    help = "Populate tracked_users, users, and the flag table."

    def handle(self, *args, **options) -> None:
        TrackedUser.objects.all().delete()
        TrackedUser.objects.create(tracking_id=SEEDED_TRACKING_ID)

        User.objects.all().delete()
        admin_password = secrets.token_urlsafe(16)
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
