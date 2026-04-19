from django.contrib import admin

from .models import Flag, Product, Stock, User

admin.site.register(Product)
admin.site.register(Stock)
admin.site.register(User)
admin.site.register(Flag)
