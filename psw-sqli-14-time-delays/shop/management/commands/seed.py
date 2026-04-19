"""
Seed the time-delay SQLi lab.

There are no users or credentials for this lab - the objective is
purely to prove that injection is possible by inducing a server-side
time delay. The seed just creates one tracked_users row (so legitimate
lookups succeed in sub-second time) and the flag row that is revealed
when the home view measures a 10+ second query.

Run inside the container:

    python manage.py seed
"""

from django.core.management.base import BaseCommand

from shop.models import Flag, TrackedUser


SEEDED_TRACKING_ID = "psw-lab-visitor-001"
FLAG_CONTENT = "FLAG{psw-sqli-14-time-delay-injection-confirmed}"


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
