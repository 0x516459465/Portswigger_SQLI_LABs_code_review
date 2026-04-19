"""
Seed the non-Oracle-contents-listing lab.

Administrator password is a random 16-byte token generated at seed
time, so the only way to discover it is the intended UNION-based
extraction. Low-privilege users have memorable passwords so the
attacker can test the login view before running the full chain.

Run inside the container:

    python manage.py seed
"""

import secrets

from django.core.management.base import BaseCommand

from shop.models import Flag, Product, User


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

LOW_PRIV_USERS = [
    ("wiener", "peter",   "wiener@example.invalid"),
    ("carlos", "montoya", "carlos@example.invalid"),
]

FLAG_CONTENT = "FLAG{psw-sqli-05-list-db-contents-admin-access}"


class Command(BaseCommand):
    help = "Populate products, users, and the flag table."

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

        User.objects.all().delete()
        admin_password = secrets.token_urlsafe(16)
        User.objects.create(
            username="administrator",
            password=admin_password,
            email="admin@example.invalid",
            is_admin=True,
        )
        for username, password, email in LOW_PRIV_USERS:
            User.objects.create(
                username=username,
                password=password,
                email=email,
                is_admin=False,
            )

        Flag.objects.all().delete()
        Flag.objects.create(content=FLAG_CONTENT)

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {len(PRODUCTS)} products, "
                f"{1 + len(LOW_PRIV_USERS)} users, 1 flag."
            )
        )
