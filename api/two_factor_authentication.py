
import random
from django.utils import timezone
from counterbookuser.models import CounterBookUser
from counterbookuser.models import TwoFactorAuthentication
from api.mailer import Mailer

class OTPAuthentication:
    """
    OTPAuthentication
    """

    def __init__(self, **kwargs):
        self.email = kwargs.get('email', None)
        self.sms_otp_expiry = timezone.timedelta(minutes=5)
        self.random_otp_number = '8392'
        self.current_date_time = timezone.now()
        self.otp = kwargs.get('otp', None)

    def get_the_otp(self):
        """get_the_otp
        this get_the_otp() methods used to generate the 4 digits random number
        for customer otp
        """
        self.random_otp_number = random.randint(1000, 9999)

    def otp_sent(self):
        """
        otp_sent
        """
        self.get_the_otp()
        try:
            mailer_obj = Mailer(
                email_id=self.email,
                otp=str(self.random_otp_number),
                subject="Here's your One Time Password (OTP) - Expire in 5 minutes!",
                type="otp"
            )
            mailer_status = mailer_obj()
            return 'delivered' if mailer_status else 'not_delivered'
        except Exception as e:
            print('G93')
            print(e)
            return 'not_delivered'

    def otp_generation(self):
        """
        otp_generation
        """
        otp_sent_status = self.otp_sent()
        create_user_otp = TwoFactorAuthentication.objects.create(
            otp=self.random_otp_number,
            otp_status= otp_sent_status,
            is_verified=False,
            expired_datetime=timezone.now() + self.sms_otp_expiry,
            email=self.email
        )
        if not create_user_otp:
            return False
        return True

    def otp_verification(self):
        """
        otp_verification
        """
        two_factor_instance = TwoFactorAuthentication.objects.filter(
            created_at__lte=self.current_date_time,
            expired_datetime__gte=self.current_date_time,
            is_verified=False,
            email=self.email).first()

        if not two_factor_instance:
            return {"status":False, "message":"otp expired"}

        if int(two_factor_instance.otp) == int(self.otp):
            two_factor_instance.is_verified = True
            two_factor_instance.save()
            user_instance = CounterBookUser.objects.get(email=self.email)
            user_instance.is_email_verified=True
            user_instance.save()
            return {"status":True, "message":"done"}
        return {"status":False, "message":"otp mismatch"}
