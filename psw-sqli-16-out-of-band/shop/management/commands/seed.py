"""
Seed the out-of-band SQLi lab.

There are no user credentials for this lab - the objective is to
cause the database to initiate an outbound TCP connection to the
`oob` recorder service on the compose network. The seed just creates
one tracked_users row (so a legitimate cookie lookup succeeds) and
the flag row that is released once the oob service has logged at
least one inbound connection.

Run inside the container:

    python manage.py seed
"""

from django.core.management.base import BaseCommand

from shop.models import Flag, TrackedUser


SEEDED_TRACKING_ID = "psw-lab-visitor-001"
FLAG_CONTENT = "FLAG{psw-sqli-16-out-of-band-interaction-captured}"


class Command(BaseCommand):
    help = "Populate tracked_users and the flag table."

    def handle(self, *args, **options) -> None:
        TrackedUser.objects.all().delete()
        TrackedUser.objects.create(tracking_id=SEEDED_TRACKING_ID)

        Flag.objects.all().delete()
        Flag.objects.create(content=FLAG_CONTENT)

        self.stdout.write(
            self.style.SUCCESS("Seeded 1 tracked user and 1 flag.")
        )
