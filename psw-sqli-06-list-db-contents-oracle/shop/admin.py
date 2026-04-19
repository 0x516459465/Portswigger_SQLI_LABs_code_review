from django.contrib import admin

from .models import Flag, Product, User

admin.site.register(Product)
admin.site.register(User)
admin.site.register(Flag)
