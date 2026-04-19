"""
Seed the XML-encoding-filter-bypass lab.

Small catalog, matching stock rows, three users. Administrator
password is a random URL-safe token; unlike the time-based
extraction labs, the intended path reads it out in a single UNION
response - there is no need for a brute-force-friendly alphabet.

Run inside the container:

    python manage.py seed
"""

import secrets

from django.core.management.base import BaseCommand

from shop.models import Flag, Product, Stock, User


PRODUCTS = [
    (
        "Clearance Lightweight Sweater",
        "Still warm enough for early autumn. Probably.",
        1999,
        42,
    ),
    (
        "Waterproof Notebook",
        "Take notes in the rain - or the bathtub.",
        1499,
        128,
    ),
    (
        "Novelty Mug (Large)",
        "Holds approximately one entire cup of coffee.",
        799,
        0,
    ),
    (
        "Company Branded Lanyard",
        "Now with 20 percent less off-brand logo.",
        299,
        512,
    ),
]

LOW_PRIV_USERS = [
    ("wiener", "peter"),
    ("carlos", "montoya"),
]

ADMIN_PASSWORD_BYTES = 12

FLAG_CONTENT = "FLAG{psw-sqli-18-filter-bypass-xml-encoding-admin-access}"


class Command(BaseCommand):
    help = "Populate products, stock, users, and the flag table."

    def handle(self, *args, **options) -> None:
        Product.objects.all().delete()
        Stock.objects.all().delete()
        for name, description, price_cents, stock_count in PRODUCTS:
            product = Product.objects.create(
                name=name,
                description=description,
                price_cents=price_cents,
            )
            Stock.objects.create(product_id=product.id, count=stock_count)

        User.objects.all().delete()
        admin_password = secrets.token_urlsafe(ADMIN_PASSWORD_BYTES)
        User.objects.create(
            username="administrator",
            password=admin_password,
            is_admin=True,
        )
        for username, password in LOW_PRIV_USERS:
            User.objects.create(
                username=username,
                password=password,
                is_admin=False,
            )

        Flag.objects.all().delete()
        Flag.objects.create(content=FLAG_CONTENT)

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {len(PRODUCTS)} products, "
                f"{len(PRODUCTS)} stock rows, "
                f"{1 + len(LOW_PRIV_USERS)} users, 1 flag."
            )
        )
