from django.contrib import admin
from .models import User, Hash

admin.site.register(User)
admin.site.register(Hash)