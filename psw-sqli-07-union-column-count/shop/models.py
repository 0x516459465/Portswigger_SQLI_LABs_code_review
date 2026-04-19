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
