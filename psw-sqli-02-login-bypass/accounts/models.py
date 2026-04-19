from django.db import models


class User(models.Model):
    """
    Application user.

    Passwords are stored in plaintext on purpose: the lab's flaw is the
    raw SQL in the login view, and plaintext passwords keep the query
    shape identical to the PortSwigger training scenario so the review
    focuses on the injection rather than on hashing mechanics.
    """

    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=200)
    email = models.EmailField(blank=True, default="")
    is_admin = models.BooleanField(default=False)

    class Meta:
        db_table = "users"

    def __str__(self) -> str:
        return self.username
