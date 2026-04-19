from django.db import models


class TrackedUser(models.Model):
    """
    Analytics table joined to the browser's TrackingId cookie.

    Seeded with one row whose value matches the cookie baked in on the
    first visit, so the legitimate request path always runs a
    sub-second query. The query result is never reflected, and any
    error is swallowed - the only signal of a successful attack is an
    out-of-band connection from the database to the oob service.
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
