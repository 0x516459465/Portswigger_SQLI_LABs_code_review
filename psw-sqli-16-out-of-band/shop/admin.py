from django.contrib import admin

from .models import Flag, TrackedUser

admin.site.register(TrackedUser)
admin.site.register(Flag)
