"""
Seed the shop with released and unreleased products.

Run inside the container:

    python manage.py seed
"""

from django.core.management.base import BaseCommand

from shop.models import Product


PRODUCTS = [
    # --- Released / public ---
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

    # --- Unreleased / hidden data ---
    ("Inflatable Moon Pants",       "Gifts",       "LAUNCHING NEXT QUARTER - DO NOT SHOW.",           29.99, False),
    ("Confidential Prototype X",    "Tech",        "Internal R&D unit. Not for customers.",          999.00, False),
    ("Secret Birthday Hamper",      "Gifts",       "Hidden gift set - reveal on release day.",        59.99, False),
    ("Unreleased Firmware Update",  "Tech",        "Embargoed patch. Internal distribution only.",     0.00, False),
    ("Staff-Only Holiday Mug",      "Lifestyle",   "Internal merch, not for sale.",                    9.99, False),

    # --- CTF flag carrier (released = False so normal browsing cannot reach it) ---
    ("Classified Dossier",          "Gifts",       "FLAG{psw-sqli-01-where-clause-hidden-gems}",       0.00, False),
]


class Command(BaseCommand):
    help = "Populate the shop with training data (released + unreleased products)."

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
        self.stdout.write(
            self.style.SUCCESS(f"Seeded {len(PRODUCTS)} products.")
        )
