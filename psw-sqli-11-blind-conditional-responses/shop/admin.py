from django.contrib import admin

from .models import Flag, TrackedUser, User

admin.site.register(TrackedUser)
admin.site.register(User)
admin.site.register(Flag)
