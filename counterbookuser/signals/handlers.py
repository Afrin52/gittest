from counterbookuser.models import Notification
from counterbookuser.models import CounterBookUser
from api.mailer import Mailer

def update_order_id(sender, instance, created, *args, **kwargs):
	if created:
		instance.order_id = 1000000 + instance.id 
		instance.save()
	else:
		pass

def update_delivery_id(sender, instance, created, *args, **kwargs):
	if created:
		instance.order_id = 1000000 + instance.id 
		instance.save()
	else:
		pass


def add_comment_notification(sender, instance, created, *args, **kwargs):
	if created:
		# notice = instance.commented_by.full_name +' commented on your '+instance.order.job_title +'.'
		# notification_instance = Notification.objects.create(edited_by=instance.order.created_by, type='Comment', message=notice, created_by=instance.commented_by)
		# if instance.order.created_by.is_email_comment:
		# 	mail_response = Mailer(email_id=instance.order.created_by.email, subject='Comment Notification', otp=notice)
		# 	_mail= mail_response()
		pass
	else:
		pass
