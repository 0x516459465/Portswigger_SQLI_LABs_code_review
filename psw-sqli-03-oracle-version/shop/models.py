from django.db import models


class Product(models.Model):
    """
    Shop catalog backed by Oracle.

    Oracle stores unquoted identifiers in uppercase, so raw SQL can
    still target this table as `products` (case-insensitive match).
    """

    name = models.CharField(max_length=200)
    category = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    released = models.BooleanField(default=True)

    class Meta:
        db_table = "products"

    def __str__(self) -> str:
        return f"{self.name} ({self.category})"


class Flag(models.Model):
    """
    Stores the CTF flag in a dedicated table.

    Normal browsing never reads from this table - only a UNION-based
    injection that discovers the schema (e.g. via ALL_TABLES) and
    projects `content` into one of the product columns can surface it.
    """

    content = models.CharField(max_length=200)

    class Meta:
        db_table = "flags"

    def __str__(self) -> str:
        return self.content
