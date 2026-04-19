"""
Seed the time-delay info-retrieval lab.

Administrator password is drawn from a short lowercase alphabet so the
learner can realistically recover it via Burp Intruder using the
response-time side channel - conditional `pg_sleep()` in the
`TrackingId` cookie lookup.

Keep the delay short (the intended payload uses 5s, not 10s) and the
password length small, because every character-guess round-trip costs
at least one sleep.

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

FLAG_CONTENT = "FLAG{psw-sqli-15-time-delay-extraction-admin-access}"


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
