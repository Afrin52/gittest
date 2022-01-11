from django import forms
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.core.exceptions import ValidationError
from datetime import datetime

from counterbookuser.models import CounterBookUser, Driver, JobOrder, UploadAttachment
from counterbookuser.models import TwoFactorAuthentication
from counterbookuser.models import ForgotPassword
from counterbookuser.models import Comment
from counterbookuser.models import OrderHistory
from counterbookuser.models import Notification
from counterbookuser.models import Delivery

class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = CounterBookUser
        fields = ('email',)

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    disabled password hash display field.
    """
    password = ReadOnlyPasswordHashField(help_text=("Django does not stores password in readable form, So you cannot see"  
                                                                        "this user's password, but you can change the password "
                                                                        "using <a href=\"../password/\">this form</a>."))

    class Meta:
        model = CounterBookUser
        fields = ('email', 'password', 'is_active', 'is_superuser')


class CounterBookUserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('email', 'full_name', 'business_name', 'business_email', 'is_superuser', 'is_staff', "is_admin", 'is_active', 'added_by')
    list_filter = ('email', 'business_email', 'full_name', 'business_name', 'phone', 'business_phone','is_superuser', 'added_by', 'is_admin', "is_staff")
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('full_name', 'username', 'phone', 'profile_picture', 'added_by')}),
        ('Business info', {'fields':('business_name', 'business_email', 'business_address', 'business_phone', 'logo', 'members')}),
        ('Permissions', {'fields': ('is_superuser', 'is_staff', 'is_active', "is_admin")}),
        ("Notification Setting", {'fields':('is_email_reminder', 'is_email_comment', 'is_email_edit', 'is_push_reminder', 'is_push_edit', 'is_push_comment')}),
        ('Dates', {'fields':('last_login', 'date_joined')})
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email',)
    filter_horizontal = ()

    def save_model(self, request, obj, form, change):
        if not change:
            obj.added_by = request.user
        obj.save()

class DriverAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'phone', 'created_at', 'created_by')
    list_filter = ('name', 'email', 'created_by')

    search_fields = ('name', 'email')

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        elif change:
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)

class JobOrderAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'job_title', 'customer_name', 'created_at', 'status', "created_by", "is_delete",  "updated_by")
    list_filter = ('status', 'created_by', "is_delivered")
    search_fields = ('order_id', 'job_title', 'customer_name')

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        elif change:
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)


class TwoFactorAuthenticationAdmin(admin.ModelAdmin):
    list_display = ("email",'otp', 'otp_status', 'is_verified','created_at', 'expired_datetime')
    list_filter = ('user', 'is_verified')

class ForgotPasswordAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'used', 'used_date')

class CommentAdmin(admin.ModelAdmin):
    list_display = ('order', 'delivery', 'commented_by', 'commented_at')
    list_filter = ('order', 'delivery', 'commented_by')

class OrderHistoryAdmin(admin.ModelAdmin):
    list_display = ('order', 'delivery', 'created_at')
    list_filter = ('order', 'delivery')

class NotificationAdmin(admin.ModelAdmin):
    list_display = ("edited_by", 'created_by', "message", "created_at", 'type')
    list_filter = ("edited_by", 'created_by')

class DeliveryAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'job_title', 'customer_name', 'delivery_date', 'delivery_time', 'created_at', 'status', "created_by", "is_delete", "is_delivered", "updated_by")
    list_filter = ('status', 'created_by', "is_delivered")
    search_fields = ('order_id', 'job_title', 'customer_name')

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        elif change:
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)

admin.site.register(CounterBookUser, CounterBookUserAdmin)
admin.site.unregister(Group)
admin.site.register(Driver, DriverAdmin)
admin.site.register(JobOrder, JobOrderAdmin)
admin.site.register(UploadAttachment)
admin.site.register(TwoFactorAuthentication, TwoFactorAuthenticationAdmin)
admin.site.register(ForgotPassword, ForgotPasswordAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(OrderHistory, OrderHistoryAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(Delivery, DeliveryAdmin)