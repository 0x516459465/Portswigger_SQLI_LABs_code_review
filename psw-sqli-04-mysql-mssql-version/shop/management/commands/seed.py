"""
Seed the MySQL-backed shop with released and unreleased products.

Run inside the container:

    python manage.py seed
"""

from django.core.management.base import BaseCommand

from shop.models import Flag, Product


FLAG_CONTENT = "FLAG{psw-sqli-04-mysql-mssql-version-revealed}"


PRODUCTS = [
    ("Vintage Neck Pillow",         "Accessories", "A pillow inspired by 1800s train travel.",        19.99, True),
    ("Folding Qwerty Keyboard",     "Tech",        "Collapsible mechanical keyboard for travellers.", 49.00, True),
    ("Single Use Food Hider",       "Lifestyle",   "Throwaway container for hiding snacks from pets.", 4.50, True),
    ("Giant Pillow Thing",          "Lifestyle",   "An enormous cushion of dubious utility.",         24.99, True),
    ("Hitch-A-Ride Parachute",      "Accessories", "Compact parachute for unplanned descents.",       89.00, True),
    ("Snow Delivered To Your Door", "Gifts",       "Authentic Alpine snow shipped overnight.",        35.00, True),
    ("Eco Polar Bear Cuddly Toy",   "Gifts",       "Recycled plush bear. Ethically stuffed.",         22.50, True),
    ("The Splash-Me-Nots",          "Gifts",       "Waterproof flowers for rainy days.",              12.00, True),
    ("Robotic Pet Dog",             "Pets",        "A dog that never needs walking.",                199.00, True),
    ("Invisible Hoodie",            "Clothing",    "You can see right through it.",                   45.00, True),
]


class Command(BaseCommand):
    help = "Populate the shop with training data."

    def handle(self, *args, **options) -> None:
        Product.objects.all().delete()
        for name, category, description, price, released in PRODUCTS:
            Product.objects.create(
                name=name,
                category=category,
                description=description,
                price=price,
                released=released,
            )

        Flag.objects.all().delete()
        Flag.objects.create(content=FLAG_CONTENT)

        self.stdout.write(
            self.style.SUCCESS(f"Seeded {len(PRODUCTS)} products and 1 flag.")
        )
