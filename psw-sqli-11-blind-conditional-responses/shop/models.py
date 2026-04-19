from django.db import models


class TrackedUser(models.Model):
    """
    Analytics table joined to the browser's TrackingId cookie.

    Seed starts with one row whose value is the cookie baked in on
    first visit - so the legitimate cookie always produces a match
    and the "Welcome back!" banner appears.
    """

    tracking_id = models.CharField(max_length=200, db_column="TrackingId")

    class Meta:
        db_table = "tracked_users"

    def __str__(self) -> str:
        return self.tracking_id


class User(models.Model):
    """
    Application user.

    Administrator password is constrained to lowercase letters and a
    short length so a learner can realistically enumerate it via the
    blind boolean side channel using Burp Intruder.
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
