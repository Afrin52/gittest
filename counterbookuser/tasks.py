from __future__ import absolute_import, unicode_literals
from api.mailer import Mailer
from counterbookuser.models import JobOrder, Delivery
from counterbookuser.models import Notification
from django.utils import timezone
from celery import shared_task
from celery.task.schedules import crontab
# @shared_task(name='notification')
from celery.decorators import periodic_task


@periodic_task(run_every=(crontab(minute='*/1')), name="notification", ignore_result=True)
# @shared_task(name='notification')
def reminder():
    for delivery in Delivery.objects.filter(is_delete=False, is_delivered=False):
        if delivery.delivery_date == timezone.now().date():
            remind = "You have a delivery at "+str(delivery.delivery_time)+"."
            Notification.objects.create(edited_by=delivery.created_by, type='Reminder', message=remind, created_by=delivery.created_by)
            if delivery.created_by.is_email_reminder:
                mail_response = Mailer(email_id=delivery.created_by.email, subject='Reminder', otp=remind)
                _mail= mail_response()
    print('Sent')