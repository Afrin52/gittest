
from datetime import datetime

from django.core.mail import EmailMultiAlternatives
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.conf import settings
from api.serializers import CounterBookUser


class Mailer:
    """
    Mailer
    """

    def __init__(self, **kwargs):
        self.email_id = kwargs.get('email_id', None)
        self.email_status = False
        self.notification_category = "EMAIL"
        self.email_subject = kwargs.get('subject', None)
        self.reason_for_failed = 'Error'
        self.subject = kwargs.get("subject", None)
        self.otp = kwargs.get('otp', None)
        self.type = kwargs.get("type", None)
        self.reset_hash = kwargs.get("reset_hash", None)
        if self.type == "otp":
            self.template_name = "otp.html"
        elif self.type == "reset":
            self.template_name = "reset_password.html"
    
    def __call__(self):
        return self.email_sender()

    def email_sender(self):
        try:
            user_instance = CounterBookUser.objects.get(email=self.email_id)
            template_data = {
                "email":self.email_id,
                "otp":self.otp,
                "full_name":user_instance.full_name,
                "reset_link":self.reset_hash
            }
            html_content = render_to_string(
                self.template_name, template_data)
            text_content = strip_tags(html_content)
            msg = EmailMultiAlternatives(self.subject,
                                         text_content,
                                         settings.EMAIL_HOST_USER,
                                         [self.email_id],
                                         )
            msg.attach_alternative(html_content, "text/html")
            return True if msg.send() else False
        except Exception as e:
            print(e)
            self.reason_for_failed = str(e)
            return False
