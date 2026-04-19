"""
Seed users for the login-bypass lab.

`administrator` is the target account. Its password is an opaque,
randomly-generated string that is not discoverable through normal
login attempts - which is the point of the lab.

Run inside the container:

    python manage.py seed
"""

import secrets

from django.core.management.base import BaseCommand

from accounts.models import User


LOW_PRIV_USERS = [
    ("wiener", "peter",   "wiener@example.invalid", False),
    ("carlos", "montoya", "carlos@example.invalid", False),
]


class Command(BaseCommand):
    help = "Populate the users table with training accounts."

    def handle(self, *args, **options) -> None:
        User.objects.all().delete()

        User.objects.create(
            username="administrator",
            password=secrets.token_urlsafe(32),
            email="FLAG{psw-sqli-02-admin-bypass-via-quote-comment}",
            is_admin=True,
        )

        for username, password, email, is_admin in LOW_PRIV_USERS:
            User.objects.create(
                username=username,
                password=password,
                email=email,
                is_admin=is_admin,
            )

        total = 1 + len(LOW_PRIV_USERS)
        self.stdout.write(self.style.SUCCESS(f"Seeded {total} users."))
