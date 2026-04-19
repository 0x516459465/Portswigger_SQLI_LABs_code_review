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


class Challenge(models.Model):
    """
    Holds the random challenge token displayed on the home page and
    the flag that is revealed when the attacker successfully surfaces
    the token through the text-rendered column.

    One row per deployment, regenerated on every `seed`.
    """

    token = models.CharField(max_length=64)
    flag = models.CharField(max_length=200)

    class Meta:
        db_table = "challenge"

    def __str__(self) -> str:
        return self.token
