from django.db import models


class Product(models.Model):
    name = models.CharField(max_length=200)
    category = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    released = models.BooleanField(default=True)

    class Meta:
        db_table = "products"

    def __str__(self) -> str:
        return f"{self.name} ({self.category})"


class User(models.Model):
    """
    Application user.

    Passwords are stored in plaintext because the lab's teaching goal
    is to recover admin credentials via UNION-based SQLi and then log
    in with them.
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
