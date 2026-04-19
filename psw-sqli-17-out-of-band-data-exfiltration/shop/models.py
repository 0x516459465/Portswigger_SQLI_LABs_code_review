from django.db import models


class TrackedUser(models.Model):
    """
    Analytics table joined to the browser's TrackingId cookie.

    Seeded with one row whose value matches the cookie baked in on the
    first visit, so the legitimate request path always runs a
    sub-second query. The query result is never reflected and any
    error is swallowed. The only signal available for exploitation is
    an out-of-band connection from the database to the oob service.
    """

    tracking_id = models.CharField(max_length=200)

    class Meta:
        db_table = "tracked_users"

    def __str__(self) -> str:
        return self.tracking_id


class User(models.Model):
    """
    Application user.

    Administrator password is a random URL-safe token. The intended
    path is to exfiltrate that password in a single shot via an
    out-of-band libpq connection (dblink_connect), rather than to
    brute force or guess it character by character.
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
