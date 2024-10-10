from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    is_verified = models.BooleanField(default=False)

class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)  # ForeignKey for multiple OTPs
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.otp}"

class UserToken(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - Token"
