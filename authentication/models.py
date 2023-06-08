from django.db import models

from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):

        if email is None:
            raise TypeError('User should have an email')

        user=self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        
        return user
    
    def create_superuser(self, email,password=None, **extra_fields):
        if password is None:
            raise TypeError('Superusers must have a password ')
        
        user=self.create_user( email, password,  **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    birth_date = models.DateField(null=True, blank=True, default=None)
    is_verified = models.BooleanField(default=False)
    is_reg_password = models.BooleanField(default=False)
    is_reg_personal_info = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["first_name", "last_name","birth_date"]
    
    objects = UserManager()
    
    def __str__(self):
        return self.email
    
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        
class Hash(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    hash = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    
    
    def __str__(self):
        return str(self.hash)