from django.contrib import admin
from .models import CustomUser, OTP, UserToken
from django.contrib.auth.admin import UserAdmin

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'is_active', 'is_staff', 'verification_status', 'date_joined']
    search_fields = ['username', 'email']
    list_filter = ['is_active', 'is_staff', 'is_verified']
    ordering = ['date_joined']

    def verification_status(self, obj):
        return 1 if obj.is_verified else 0
    verification_status.short_description = 'Is Verified'

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['user', 'otp', 'created_at']
    search_fields = ['user__email']
    ordering = ['created_at']

@admin.register(UserToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'token', 'created_at']
    search_fields = ['user__email']
    ordering = ['created_at']
