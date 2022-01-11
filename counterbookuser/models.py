from os import ttyname
from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)
from django.utils import timezone
import random
import string
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_phone(value):
    if ((len(value)) <= 8) or ((len(value)) >= 20):
        raise ValidationError(
            _('%(value)s is not a valid phone number.'),
            params={'value': value},
        )

def generate_hash():
	return ''.join(random.choice(string.ascii_lowercase) for i in range(25))

def expired_at():
	return timezone.now() + timezone.timedelta(days=1)
# Create your models here.
class CounterBookUserManager(BaseUserManager):

    def create_user(self, email, password=None):
    	
        if not email:
            raise ValueError('Email Field is required.')
        if not password or password is None:
        	raise ValueError("Password Field is required.")

        user = self.model(
            email=self.normalize_email(email)
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):

        if not email:
            raise ValueError('Email Field is required.')
        if not password or password is None:
        	raise ValueError("Password Field is required.")

        user = self.create_user(
            email,
            password=password
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class CounterBookUser(AbstractBaseUser):

	business_name = models.CharField(max_length=255, null=True, blank=True)
	business_address = models.TextField(null=True, blank=True)
	business_email = models.EmailField(null=True, blank=True)
	business_phone = models.CharField(max_length=20, null=True, blank=True, validators=[validate_phone])
	logo = models.ImageField(upload_to='logo/', null=True, blank=True)
	full_name = models.CharField(max_length=255, null=True, blank=True)
	email = models.EmailField(max_length=255,
    	unique=True, db_index=True)
	username = models.CharField(max_length=255, null=True, blank=True)
	job_title = models.CharField(max_length=255, null=True, blank=True)
	phone = models.CharField(max_length=20, null=True, blank=True, validators=[validate_phone])
	profile_picture = models.FileField(upload_to="user_pictures",
                                       null=True, blank=True)
	is_active = models.BooleanField(default=True)
	is_staff = models.BooleanField(default=False)
	is_admin = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)
	last_login = models.DateTimeField(null=True, blank=True)
	date_joined = models.DateTimeField(default=timezone.now)
	#notification setting
	is_email_comment = models.BooleanField(default=False)
	is_email_reminder = models.BooleanField(default=False)
	is_email_edit = models.BooleanField(default=False)
	is_push_comment = models.BooleanField(default=False)
	is_push_reminder = models.BooleanField(default=False)
	is_push_edit = models.BooleanField(default=False)
	is_email_verified = models.BooleanField(default=False)
	is_completed = models.BooleanField(default=False)
	is_picture = models.BooleanField(default=False)

	added_by = models.ForeignKey("CounterBookUser", on_delete=models.CASCADE, null=True, blank=True, related_name='add')
	members = models.ManyToManyField("CounterBookUser", blank=True, related_name='team_members')

	objects = CounterBookUserManager()

	USERNAME_FIELD = 'email'
	EMAIL_FIELD = 'email'
	REQUIRED_FIELD = []

	def __str__(self):
		return str(self.email)

	def has_perm(self, perm, obj=None):
		"Does the user have a specific permission?"
		# Simplest possible answer: Yes, always
		return True

	def has_module_perms(self, app_label):
		"Does the user have permissions to view the app `app_label`?"
		# Simplest possible answer: Yes, always
		return True


	class Meta:
		verbose_name = "Counter Book User"
		verbose_name_plural = "Counter Book Users"

class Driver(models.Model):
	name = models.CharField(max_length=255)
	email = models.EmailField(null=True, blank=True)
	phone = models.CharField(max_length=20, null=True, blank=True, validators=[validate_phone])
	created_at = models.DateTimeField(auto_now_add=True)
	created_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)

	def __str__(self):
		return self.name

	class Meta:
		verbose_name = "Driver"
		verbose_name_plural = "Drivers"

class UploadAttachment(models.Model):
	file = models.FileField(upload_to='job_attachment/', null=True, blank=True)

	def __str__(self):
		return str(self.id)

	class Meta:
		verbose_name = "Upload Attachment"
		verbose_name_plural = "Upload Attachments"

class JobOrder(models.Model):

	STATUS_CHOICES = (
		('Active', 'Active'),
		('Pending', 'Pending'),
		('PendingPickup', 'PendingPickup'),
		('Completed', 'Completed'),
	)
	order_id = models.PositiveIntegerField(null=True, blank=True)
	job_title = models.CharField(max_length=255, null=True, blank=True)
	customer_name = models.CharField(max_length=255, null=True, blank=True)
	phone = models.CharField(max_length=20, null=True, blank=True, validators=[validate_phone])
	status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Active')
	# delivery_address = models.CharField(max_length=255, null=True, blank=True)
	# delivery_date = models.DateField()
	# delivery_time = models.TimeField()
	is_delete = models.BooleanField(default=False)
	is_delivered = models.BooleanField(default=False)
	is_send = models.BooleanField(default=False)
	description = models.TextField(null=True, blank=True)
	attachment = models.ManyToManyField(UploadAttachment, blank=True)
	pdf_path = models.FileField(upload_to='orders_pdf/', null=True, blank=True)
	created_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)
	order_time = models.TimeField(auto_now_add=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True, related_name='order_update')
	updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

	def __str__(self):
		return str(self.job_title)

	class Meta:
		verbose_name = "Job Order"
		verbose_name_plural = "Job Orders"

class Delivery(models.Model):

	STATUS_CHOICES = (
		('Active', 'Active'),
		('Completed', 'Completed'),
	)
	order_id = models.PositiveIntegerField(null=True, blank=True)
	job_title = models.CharField(max_length=255, null=True, blank=True)
	customer_name = models.CharField(max_length=255, null=True, blank=True)
	phone = models.CharField(max_length=20, null=True, blank=True, validators=[validate_phone])
	status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Active')
	delivery_address = models.CharField(max_length=255, null=True, blank=True)
	delivery_date = models.DateField()
	delivery_time = models.TimeField()
	is_delete = models.BooleanField(default=False)
	is_delivered = models.BooleanField(default=False)
	is_send = models.BooleanField(default=False)
	is_send_driver = models.BooleanField(null=True, blank=True)
	description = models.TextField(null=True, blank=True)
	# comment = models.TextField(null=True, blank=True)
	attachment = models.ManyToManyField(UploadAttachment, blank=True)
	pdf_path = models.FileField(upload_to='deliveries_pdf/', null=True, blank=True)
	driver = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True, related_name="driver_user")
	created_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True, related_name="creator_user")
	created_at = models.DateTimeField(auto_now_add=True)
	updated_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True, related_name='delivery_update')
	updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

	def __str__(self):
		return str(self.job_title)

	class Meta:
		verbose_name = "Delivery"
		verbose_name_plural = "Deliveries"

class TwoFactorAuthentication(models.Model):
	"""
	TwoFactorAuthentication email 
	authentication module
	"""
	otp = models.PositiveIntegerField()
	otp_status = models.CharField(
        max_length=20,
        verbose_name='OTP Status',
        choices=[
            ('delivered', 'Delivered'),
            ('not_delivered', 'Not Delivered'),
            ('successful', 'Successful'),
            ('expired', 'Expired')
        ]
    )
	is_verified = models.BooleanField(default=False)
	email = models.EmailField(null=True, blank=True)
	created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Created At')
	expired_datetime = models.DateTimeField(verbose_name="Expired At")
	user = models.ForeignKey(
        CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)
	class Meta:
		verbose_name = 'Two Factor Authentication'
		verbose_name_plural = 'Two Factor Authentication'
		db_table = 'two_factor_authentication'
		ordering = ['-created_at']
		
	def __str__(self):
		return str(self.otp)

class ForgotPassword(models.Model):
	user = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)
	reset_hash = models.CharField(max_length=255, default=generate_hash)
	used = models.BooleanField(default=False)
	used_date = models.DateTimeField(null=True, blank=True)
	valid_till = models.DateTimeField(default=expired_at)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return str(self.user)

	class Meta:
		verbose_name = "Forgot Password"
		verbose_name_plural = "Forgot Passwords"

class Comment(models.Model):
	order = models.ForeignKey(JobOrder, related_name='order_comment', on_delete=models.CASCADE, null=True, blank=True)
	delivery = models.ForeignKey(Delivery, related_name='delivery_comment', on_delete=models.CASCADE, null=True, blank=True)
	comment = models.TextField()
	commented_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)
	commented_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return str(self.order)

	class Meta:
		verbose_name = "Comment"
		verbose_name_plural = "Comments"

class OrderHistory(models.Model):
	order = models.ForeignKey(JobOrder, on_delete=models.CASCADE, related_name='order_history', null=True, blank=True)
	delivery = models.ForeignKey(Delivery, on_delete=models.CASCADE, related_name='delivery_history', null=True, blank=True)
	line_text = models.CharField(max_length=255)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return str(self.order)

	class Meta:
		verbose_name = "Order History"
		verbose_name_plural = "Order Histories"


class Notification(models.Model):
	TYPE_CHOICE = (
		('Reminder', 'Reminder'),
		('Edit', 'Edit'),
		('Comment', 'Comment'),
		("Create", "Create"),
		)

	edited_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, related_name='notification_user')
	message = models.TextField()
	type = models.CharField(max_length=10, choices=TYPE_CHOICE, null=True, blank=True)
	is_read = models.BooleanField(default=False)
	created_by = models.ForeignKey(CounterBookUser, on_delete=models.CASCADE, null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	def __str__(self):
		return str(self.edited_by)

	class Meta:
		verbose_name = "Notification"
		verbose_name_plural = "Notifications"