from django.apps import AppConfig
from django.db.models.signals import post_save

class CounterbookuserConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'counterbookuser'

    def ready(self):
    	from counterbookuser.models import JobOrder, Comment, Delivery
    	from counterbookuser.signals.handlers import update_order_id, add_comment_notification, update_delivery_id
    	post_save.connect(update_order_id, sender=JobOrder, dispatch_uid='update_order_id')
    	post_save.connect(add_comment_notification, sender=Comment, dispatch_uid='add_comment_notification')
    	post_save.connect(update_delivery_id, sender=Delivery, dispatch_uid='update_delivery_id')