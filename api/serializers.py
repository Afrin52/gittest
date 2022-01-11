from django.http.response import JsonResponse
from rest_framework.serializers import ModelSerializer, SerializerMethodField
from counterbookuser.models import CounterBookUser, Driver, UploadAttachment, JobOrder
from counterbookuser.models import Comment
from counterbookuser.models import OrderHistory
from counterbookuser.models import Notification
from counterbookuser.models import Delivery

class CounterBookUserSerializer(ModelSerializer):
	class Meta:
		model = CounterBookUser
		fields = "__all__"


class UserDetail(ModelSerializer):
	class Meta:
		model = CounterBookUser
		fields = ("id", "full_name", 'email', 'job_title', "profile_picture")

class LoginSerializer(ModelSerializer):
	class Meta:
		model = CounterBookUser
		fields = ('email', "password")

class DriverSerializer(ModelSerializer):
	class Meta:
		model = Driver
		fields = "__all__"

class UplaodAttachmentSerializer(ModelSerializer):
	class Meta:
		model = UploadAttachment
		fields = "__all__"

class JobOrderSerializer(ModelSerializer):
	class Meta:
		model = JobOrder
		fields = "__all__"

class DeliverySerializer(ModelSerializer):
	class Meta:
		model = Delivery
		fields = "__all__"

class CommentSerializer(ModelSerializer):

	class Meta:
		model = Comment
		fields = "__all__"

class OrderHistorySerializer(ModelSerializer):
	class Meta:
		model = OrderHistory
		fields = "__all__"

class CommentDetail(ModelSerializer):
	commented_by = UserDetail()

	class Meta:
		model = Comment
		fields = "__all__"

class DriverUserSerializer(ModelSerializer):

	class Meta:
		model = CounterBookUser
		fields = ("id", "full_name", "email", "phone", "profile_picture")


class OrderDetailSerializer(ModelSerializer):
	attachment = UplaodAttachmentSerializer(many=True)
	comments = SerializerMethodField()
	order_history = SerializerMethodField()
	created_by = DriverUserSerializer()
	updated_by = SerializerMethodField()

	def get_comments(self, instance):
		return CommentDetail(instance.order_comment.all(), many=True).data

	def get_order_history(self, instance):
		return OrderHistorySerializer(instance.order_history.all(), many=True).data

	def get_updated_by(self, instance):
		if instance.updated_by:
			return str(instance.updated_by.id)
		else:
			return "null"

	class Meta:
		model = JobOrder
		fields = "__all__"

class DeliveryDetailSerializer(ModelSerializer):
	driver = DriverUserSerializer()
	attachment = UplaodAttachmentSerializer(many=True)
	comments = SerializerMethodField()
	delivery_history = SerializerMethodField()
	created_by = DriverUserSerializer()
	updated_by = SerializerMethodField()

	def get_comments(self, instance):
		return CommentDetail(instance.delivery_comment.all(), many=True).data

	def get_delivery_history(self, instance):
		return OrderHistorySerializer(instance.delivery_history.all(), many=True).data

	def get_updated_by(self, instance):
		if instance.updated_by:
			return str(instance.updated_by.id)
		else:
			return "null"

	class Meta:
		model = Delivery
		fields = "__all__"

class NotificationSerializer(ModelSerializer):
	edited_by = DriverUserSerializer()
	created_by = DriverUserSerializer()

	class Meta:
		model = Notification
		fields = "__all__"

class PostNotificationSerializer(ModelSerializer):

	class Meta:
		model = Notification
		fields = "__all__"


class NotificationSettingSerializer(ModelSerializer):
	class Meta:
		model = CounterBookUser
		fields = ('id', 'is_email_reminder', 'is_email_edit', 'is_email_comment', 'is_push_reminder', 'is_push_edit', 'is_push_comment')

class MemberSerializer(ModelSerializer):
	class Meta:
		model = CounterBookUser
		fields = ("id", "full_name", "email")

class GetUserSerializer(ModelSerializer):
	orders = SerializerMethodField()
	deliveries = SerializerMethodField()
	members = SerializerMethodField()
	added_by = SerializerMethodField()

	def get_orders(self, instance):
		return JobOrder.objects.filter(created_by__email=instance.email, is_delete=False, is_delivered=False).count()

	def get_deliveries(self, instance):
		return Delivery.objects.filter(created_by__email=instance.email, is_delete=False, is_delivered=False).count()

	def get_members(self, instance):
		return MemberSerializer(instance.members.all(), many=True).data
	
	def get_added_by(self, instance):
		if instance.added_by:
			return str(instance.added_by.id)
			
		else:
			return "null"
	class Meta:
		model = CounterBookUser
		fields = ("id", "business_name", "business_address", "business_email", "business_phone", "logo", "full_name", "email",
		"username", "job_title", "phone", "profile_picture", "is_active", "is_staff", "is_superuser", "is_admin", "last_login", "date_joined",
		"is_email_comment", "is_email_reminder", "is_email_edit", "is_push_comment", "is_push_reminder", "is_push_edit", "added_by",
		"members", "orders", "deliveries", "is_email_verified", "is_completed", "is_picture")
