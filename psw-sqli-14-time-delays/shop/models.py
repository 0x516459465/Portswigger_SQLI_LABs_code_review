from django.db import models


class TrackedUser(models.Model):
    """
    Analytics table joined to the browser's TrackingId cookie.

    Seeded with one row whose value matches the cookie baked in on
    first visit, so the legitimate request path always runs a
    sub-second query. The query result is never reflected - the table
    exists only so the vulnerable statement has a real relation to read
    from.
    """

    tracking_id = models.CharField(max_length=200)

    class Meta:
        db_table = "tracked_users"

    def __str__(self) -> str:
        return self.tracking_id


class Flag(models.Model):
    content = models.CharField(max_length=200)

    class Meta:
        db_table = "flags"

    def __str__(self) -> str:
        return self.content
