from django.db import models


class TrackedUser(models.Model):
    """
    Analytics table joined to the browser's TrackingId cookie.

    Seeded with one row whose value matches the cookie baked in on
    first visit so the legitimate lookup succeeds silently. The lookup
    result is never rendered - the purpose of this table is only to
    give the vulnerable query a real relation to read from, so the
    attacker can chain it into conditional error payloads.
    """

    tracking_id = models.CharField(max_length=200, db_column="TrackingId")

    class Meta:
        db_table = "tracked_users"

    def __str__(self) -> str:
        return self.tracking_id


class User(models.Model):
    """
    Application user.

    Administrator password uses a short lowercase alphabet so the blind
    extraction via conditional SQL errors is tractable with Burp
    Intruder but still requires real exploitation of the side channel.
    """

    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=200)
    is_admin = models.BooleanField(default=False)

    class Meta:
        db_table = "users"

    def __str__(self) -> str:
        return self.username


class Flag(models.Model):
    content = models.CharField(max_length=200)

    class Meta:
        db_table = "flags"

    def __str__(self) -> str:
        return self.content
