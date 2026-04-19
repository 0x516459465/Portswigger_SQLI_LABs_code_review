from django.db import models


class Product(models.Model):
    """Catalog item shown on the home page."""

    name = models.CharField(max_length=200)
    description = models.CharField(max_length=500)
    price_cents = models.IntegerField(default=0)

    class Meta:
        db_table = "products"

    def __str__(self) -> str:
        return self.name


class Stock(models.Model):
    """
    Stock level used by the vulnerable stock-check endpoint.

    The endpoint concatenates the productId pulled out of the XML
    request body directly into `SELECT count FROM stock WHERE
    product_id = <productId>`. Under SQLite, a UNION against the
    `users` table will reflect the administrator password through
    the same response field, because SQLite unions across mixed
    types without complaining.
    """

    product_id = models.IntegerField()
    count = models.IntegerField(default=0)

    class Meta:
        db_table = "stock"

    def __str__(self) -> str:
        return f"stock[{self.product_id}] = {self.count}"


class User(models.Model):
    """Application user. Administrator password is a random URL-safe token."""

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
