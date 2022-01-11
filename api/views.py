
from django.conf import settings
from django.core.checks import messages
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import serializers, status
from rest_framework.viewsets import ModelViewSet
from django.contrib.auth import authenticate, login, logout
from api.serializers import CommentDetail, CounterBookUserSerializer, LoginSerializer, LoginSerializer,\
			DriverSerializer, UplaodAttachmentSerializer, JobOrderSerializer, OrderDetailSerializer, GetUserSerializer, DriverUserSerializer
from counterbookuser.models import CounterBookUser, Driver, JobOrder, UploadAttachment
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, BasePermission
from django.views.decorators.csrf import csrf_exempt
from api.two_factor_authentication import OTPAuthentication
from counterbookuser.models import ForgotPassword
from django.utils import timezone
from api.serializers import CommentSerializer, OrderHistorySerializer
from counterbookuser.models import Comment, OrderHistory, Notification
from api.serializers import NotificationSerializer, NotificationSettingSerializer
from django.db.models import Q, Max, Min
from api.mailer import Mailer
from api.push_notification import send_notification
from counterbookuser.models import Delivery
from api.serializers import DeliveryDetailSerializer, DeliverySerializer
from counterbookuser.models import TwoFactorAuthentication
import math
# from api.generate_pdf import GeneratePDF
import os
from django.core.files.base import ContentFile

# from pyfcm import FCMNotification
# from counterbookuser.tasks import print_hello

# proxy_dict = {
# "http"  : "http://127.0.0.1:8000",
# "https" : "http://127.0.0.1:8000",
# }
# api_key = " AAAAyf5-org:APA91bG4Utl8gTk5yzDC_K6v6WUfJ4PEyOhN9bklqclhCw1gCke1zZjpqWzBBlTuJNurleEIWAyop5WhUfbuwluEAx2MQip0PtShc32qLlWPlBWz3m4NTXyzKn41l817bK66t5f-q_Nu"
# push_service = FCMNotification(api_key=api_key, proxy_dict=proxy_dict)
# device_1 = "AAAA8lRYGGg:APA91bHJXPJbe-5MN1O4Cf3pEDikOpYrgrX4UxvS-DeDcPndaseh9_51fWuaqbkPKgOIrpCboDNpBn6T5jSxU6DwKtLhdzim0C5w9Xqh1nvdfvAr4_2iqNtcsEhZmOOgoNtbEYQpoUph"
# registration_ids = [device_1]
# message_title = "Uber update"
# message_body = "Hope you're having fun this weekend, don't forget to check today's news"
# result = push_service.notify_single_device(registration_id=registration_ids, message_title=message_title, message_body=message_body)
# print("result------>", result)


class IsCreator(BasePermission):
	def has_object_permission(self, request, view, obj):
		return bool(request.user and obj.created_by == request.user)

def getFirstError(errors):
    message = ""
    for error in errors:
        if isinstance(errors[error], dict):
            for error2 in errors[error]:
                message = errors[error][error2][0]
        else:
            if isinstance(errors[error][0], dict):
                for error2 in errors[error][0]:
                    message =  errors[error][0][error2][0]
            else:
                if errors[error][0].startswith('This'):
                    message = error + errors[error][0][4:]
                else:
                    message =  errors[error][0]
    return {"message" : message}

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_user(request, id):
	if request.method == "GET":
		user_instance = CounterBookUser.objects.get(id=id)
		return Response(GetUserSerializer(user_instance).data, status=status.HTTP_200_OK)


@api_view(['PATCH', "GET"])
@permission_classes([IsAuthenticated])
def update_user(request, id):
	if request.method == "GET":
		user_instance = CounterBookUser.objects.get(id=id)
		return Response(GetUserSerializer(user_instance).data, status=status.HTTP_200_OK)
	elif request.method == "PATCH":
		print(request.data)
		user_instance = CounterBookUser.objects.get(id=id)
		serializer = CounterBookUserSerializer(user_instance, data=request.data, partial=True)
		if serializer.is_valid():
			serializer.save()
			return Response({"user":GetUserSerializer(CounterBookUser.objects.get(id=id)).data}, status=status.HTTP_200_OK)
		return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)
		
class CreateUser(ModelViewSet):

	queryset = CounterBookUser.objects.all()
	serializer_class = CounterBookUserSerializer

	def create(self, request, *args, **kwargs):
		data = self.request.data
		print(data)
		lower_email = data["email"].lower()
		print(lower_email)
		data['email'] = lower_email
		print(data['email'])
		if request.user.is_authenticated:
			data["added_by"]= request.user.id
		if CounterBookUser.objects.filter(email=lower_email).exists():
			return Response({"message":"Email already exists."}, status=status.HTTP_400_BAD_REQUEST)
		else:
			serializer = CounterBookUserSerializer(data=data)
			if serializer.is_valid():
				SpecialSym =['$', '@', '#', '%', '-', '_']
				password = data["password"]
				if(len(str(password)) < 8):
					return Response({"message":"Password should be at least 8 characters."}, status=status.HTTP_400_BAD_REQUEST)
				elif (len(str(password)) > 32):
					return Response({"message":"Password should be not be greater than 20 characters."}, status=status.HTTP_400_BAD_REQUEST)
				elif(not any(char.isdigit() for char in str(password))):
					return Response({"message":"Password should have at least one numeral."}, status=status.HTTP_400_BAD_REQUEST)
				elif (not any(char.isupper() for char in str(password))):
					return Response({"message":"Password should have at least one uppercase letter."}, status=status.HTTP_400_BAD_REQUEST)
				elif (not any(char.islower() for char in str(password))):
					return Response({"message":"Password should have at least one lowercase letter."}, status=status.HTTP_400_BAD_REQUEST)
				elif (not any(char in SpecialSym for char in str(password))):
					return Response({"message":"Password should have at least one of the special characters."}, status=status.HTTP_400_BAD_REQUEST)
				else:
					serializer.save()
					user_instance = CounterBookUser.objects.get(id=serializer.data["id"])
					user_instance.set_password(data['password'])
					user_instance.save()
					token = Token.objects.create(user=user_instance)
					_data = serializer.data
					_data["token"] = token.key
					return Response(_data, status=status.HTTP_200_OK)
			return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

class DriverViewSet(ModelViewSet):

	queryset = Driver.objects.all()
	serializer_class = DriverSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get', 'head', 'option', 'post', 'patch', 'put', 'delete']

	def perform_create(self, serializer):
		serializer.save(created_by=self.request.user)

class SelectDriverViewSet(ModelViewSet):

	serializer_class = DriverSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def get_queryset(self):
		members = CounterBookUser.objects.filter(members__id=self.request.user.id)
		return Driver.objects.filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by))

# class UploadAttachmentViewSet(ModelViewSet):

# 	queryset = UploadAttachment.objects.all()
# 	serializer_class = UplaodAttachmentSerializer
# 	permission_classes = [IsAuthenticated]

class JobOrderViewSet(ModelViewSet):

	queryset = JobOrder.objects.all()
	serializer_class = JobOrderSerializer
	permission_classes = [IsAuthenticated]

	def create(self, request, *args, **kwargs):
		data = self.request.data
		data["created_by"] = request.user.id
		serializer = JobOrderSerializer(data=data)
		if serializer.is_valid():
			serializer.save()
			order_instance = JobOrder.objects.get(id=serializer.data['id'])
			# context = {"order":order_instance}
			# gen_pdf = GeneratePDF(context=context, type="order")
			# myfile = ContentFile(gen_pdf())
			# order_instance.pdf_path.save("order_"+str(order_instance.order_id)+".pdf", myfile)
			if order_instance.is_send:
				msg = order_instance.job_title + " created." + " Send a receipt to the customer."
				Notification.objects.create(edited_by=request.user, type='Create', message=msg, created_by=request.user)
			data = OrderDetailSerializer(order_instance).data
			return Response({"data":data}, status=status.HTTP_200_OK)
		return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

	def partial_update(self, request, pk=None):
		data = self.request.data
		job_instance = JobOrder.objects.get(id=pk)
		job_instance.job_title = data.get('job_title')
		job_instance.customer_name = data.get('customer_name')
		job_instance.phone=data.get('phone')
		job_instance.description=data.get('description')
		job_instance.status = data.get('status')
		job_instance.updated_by= self.request.user
		job_instance.updated_at = timezone.now()
		job_instance.save()

		if data.get('attachment'):
			for file in data.get('attachment'):
				job_instance.attachment.add(file)
				job_instance.save()
		msg = str(request.user.full_name) +" made an edit on your "+job_instance.job_title+'.'
		Notification.objects.create(edited_by=request.user, type='Edit', message=msg, created_by=job_instance.created_by)
		if job_instance.created_by.is_email_edit:
			mail_response = Mailer(email_id=job_instance.created_by.email, subject='Edit Notification', otp=msg)
			_mail= mail_response()
		return Response(OrderDetailSerializer(job_instance).data,status=status.HTTP_200_OK)

class DeliveryViewSet(ModelViewSet):

	queryset = Delivery.objects.all()
	serializer_class = DeliverySerializer
	permission_classes = [IsAuthenticated]

	def create(self, request, *args, **kwargs):
		data = self.request.data
		data["created_by"] = request.user.id
		serializer = DeliverySerializer(data=data)
		if serializer.is_valid():
			serializer.save()
			delivery_instance = Delivery.objects.get(id=serializer.data["id"])
			# context = {"order":delivery_instance}
			# gen_pdf = GeneratePDF(context=context, type="delivery")
			# myfile = ContentFile(gen_pdf())
			# delivery_instance.pdf_path.save("delivery_"+str(delivery_instance.order_id)+".pdf", myfile)
			if delivery_instance.is_send:
				msg = delivery_instance.job_title + " created." + " Send a receipt to the customer."
				Notification.objects.create(edited_by=request.user, type='Create', message=msg, created_by=request.user)
			if request.data["driver_id"]:
				driver_id = request.data["driver_id"]
				user_instance = CounterBookUser.objects.get(id=driver_id)
				delivery_instance.driver = user_instance
				delivery_instance.save()
			data = DeliveryDetailSerializer(delivery_instance).data
			return Response({"data":data}, status=status.HTTP_200_OK)
		return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

	def partial_update(self, request, pk=None):
		data = self.request.data
		job_instance = Delivery.objects.get(id=pk)
		job_instance.job_title = data.get('job_title')
		job_instance.customer_name = data.get('customer_name')
		job_instance.phone=data.get('phone')
		job_instance.delivery_address=data.get('delivery_address')
		job_instance.delivery_date=data.get('delivery_date')
		job_instance.delivery_time=data.get('delivery_time')
		job_instance.description=data.get('description')
		job_instance.status = data.get('status')
		job_instance.updated_by= self.request.user
		job_instance.updated_at = timezone.now()
		job_instance.save()
		# if data.get('driver'):
		# 	driver_instance = Driver.objects.get(id=data.get('driver'))
		# 	job_instance.driver=driver_instance
		# 	job_instance.save()

		if data.get('attachment'):
			for file in data.get('attachment'):
				job_instance.attachment.add(file)
				job_instance.save()
		msg = str(request.user.full_name) +" made an edit on your "+job_instance.job_title+'.'
		Notification.objects.create(edited_by=request.user, type='Edit', message=msg, created_by=job_instance.created_by)
		if job_instance.created_by.is_email_edit:
			mail_response = Mailer(email_id=job_instance.created_by.email, subject='Edit Notification', otp=msg)
			_mail= mail_response()
		return Response(DeliveryDetailSerializer(job_instance).data,status=status.HTTP_200_OK)


class OrderDetailViewSet(ModelViewSet):

	
	serializer_class = OrderDetailSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def get_queryset(self):
		members = CounterBookUser.objects.filter(added_by=self.request.user.id)
		return JobOrder.objects.filter(is_delete=False, is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)).order_by('-created_at')

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def order_detail(request, id):
	order_instance = JobOrder.objects.get(id=id)
	data = OrderDetailSerializer(order_instance)
	return Response({"data":data.data}, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def delivery_detail(request, id):
	delivery_instance = Delivery.objects.get(id=id)
	data = DeliveryDetailSerializer(delivery_instance).data
	return Response({"data":data}, status=status.HTTP_200_OK)


class DeliveryDetailViewSet(ModelViewSet):

	serializer_class = DeliveryDetailSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def get_queryset(self):
		members = CounterBookUser.objects.filter(added_by=self.request.user.id)
		return Delivery.objects.filter(is_delete=False, is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)).order_by("-created_at")

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_comment(request):
	data = request.data
	serializer = CommentSerializer(data=request.data)
	if serializer.is_valid():
		serializer.save()
		comment_instance = Comment.objects.get(id=serializer.data["id"])
		comment_instance.commented_by= request.user
		comment_instance.save()
		
		if comment_instance.order:
			create = comment_instance.order.created_by
			job = comment_instance.order.job_title
		elif comment_instance.delivery:
			create = comment_instance.delivery.created_by
			job = comment_instance.delivery.job_title

		msg = str(request.user.full_name) + " commented on your " + str(job) +'.'
		Notification.objects.create(edited_by=request.user, type="Comment", message=msg, created_by=create)
		data = CommentDetail(comment_instance).data
		return Response({"data":data}, status=status.HTTP_200_OK)
	return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def update_comment(request, id):
	data_instance = Comment.objects.get(id=id)
	serializer = CommentSerializer(data_instance, request.data, partial=True)
	if serializer.is_valid():
		serializer.save()
		# if data_instance.order:
		# 	create = data_instance.order.created_by
		# 	job = data_instance.order.job_title
		# elif data_instance.delivery:
		# 	create = data_instance.delivery.created_by
		# 	job = data_instance.delivery.job_title
		# msg = str(request.user.full_name) + " made an edit on your " + str(job) +'.'
		# Notification.objects.create(edited_by=request.user, type="Comment", message=msg, created_by=create)
		data = CommentDetail(Comment.objects.get(id=id)).data
		return Response({"data":data}, status=status.HTTP_200_OK)
	return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_comment(request, id):
	data_instance = Comment.objects.get(id=id)
	data_instance.delete()
	return Response({"message":"Comment deleted successfully."}, status=status.HTTP_200_OK)


class OrderHistoryViewSet(ModelViewSet):

	queryset = OrderHistory.objects.all()
	serializer_class = OrderHistorySerializer
	permission_classes = [IsAuthenticated]

class OrderFilter(ModelViewSet):

	queryset = JobOrder.objects.all()
	serializer_class = OrderDetailSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def list(self, request, *args, **kwargs):
		_status = self.request.query_params.get('status', None)
		_search = self.request.query_params.get('search', None)
		members = []
		if self.request.user.added_by:
			members = CounterBookUser.objects.filter(Q(added_by=self.request.user)|Q(added_by=self.request.user.added_by))
		else:
			members = CounterBookUser.objects.filter(added_by=self.request.user)

		order_count = JobOrder.objects.filter(created_by=self.request.user, is_delete=False, is_delivered=False).count()
		if _search and _status:
			_data = self.serializer_class(JobOrder.objects.filter(status=_status, is_delivered=False, is_delete=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by)).filter(Q(job_title__icontains=_search) |Q(customer_name__icontains=_search)|
				Q(phone__icontains=_search)|Q(order_id__icontains=_search)|Q(description__icontains=_search)).order_by("-created_at"), many=True).data
			return Response({"data":_data, "order_count":order_count}, status=status.HTTP_200_OK)
		elif _status:
			_data = self.serializer_class(JobOrder.objects.filter(status=_status, is_delivered=False, is_delete=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by)).order_by("-created_at"), many=True).data
			return Response({'data':_data, "order_count":order_count}, status=status.HTTP_200_OK)
		elif _search:
			_data = self.serializer_class(JobOrder.objects.filter(is_delivered=False, is_delete=False).filter(Q(created_by__in=members)|Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)).filter(Q(job_title__icontains=_search) |Q(customer_name__icontains=_search)|
				Q(phone__icontains=_search)|Q(order_id__icontains=_search)|Q(description__icontains=_search)).order_by("-created_at"), many=True).data
			return Response({"data":_data, "order_count":order_count}, status=status.HTTP_200_OK)
		else:
			_data = []
			return Response({'data':_data}, status=status.HTTP_400_BAD_REQUEST)


class DeliveryFilter(ModelViewSet):

	queryset = Delivery.objects.all()
	serializer_class = DeliveryDetailSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def list(self, request, *args, **kwargs):
		_status = self.request.query_params.get('status', None)
		_search = self.request.query_params.get('search', None)
		members = []
		if self.request.user.added_by:
			members = CounterBookUser.objects.filter(Q(added_by=self.request.user)|Q(added_by=self.request.user.added_by))
		else:
			members = CounterBookUser.objects.filter(added_by=self.request.user)
		delivery_count = Delivery.objects.filter(created_by=self.request.user, is_delete=False, is_delivered=False).count()
		if _search and _status:
			_data = self.serializer_class(Delivery.objects.filter(status=_status, is_delivered=False, is_delete=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by)).filter(Q(job_title__icontains=_search) |Q(customer_name__icontains=_search)|
				Q(phone__icontains=_search)|Q(order_id__icontains=_search)|Q(description__icontains=_search)).order_by("-created_at"), many=True).data
			return Response({"data":_data, "delivery_count":delivery_count}, status=status.HTTP_200_OK)
		elif _status:
			_data = self.serializer_class(Delivery.objects.filter(status=_status, is_delete=False, is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by)).order_by("-created_at"), many=True).data
			return Response({'data':_data, "delivery_count":delivery_count}, status=status.HTTP_200_OK)
		elif _search:
			_data = self.serializer_class(Delivery.objects.filter(is_delivered=False, is_delete=False).filter(Q(created_by=self.request.user)|Q(created_by__in=members)|Q(created_by=self.request.user.added_by)).filter(Q(job_title__icontains=_search) |Q(customer_name__icontains=_search)|
				Q(phone__icontains=_search)|Q(order_id__icontains=_search)|Q(description__icontains=_search)).order_by("-created_at"), many=True).data
			return Response({"data":_data, "delivery_count":delivery_count}, status=status.HTTP_200_OK)
		else:
			_data = []
			return Response({'data':_data}, status=status.HTTP_400_BAD_REQUEST)

class TeamMembersViewSet(ModelViewSet):

	serializer_class = CounterBookUserSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def get_queryset(self):
		return CounterBookUser.objects.filter(added_by=self.request.user)

class Logout(APIView):
	permission_classes = [IsAuthenticated]
	def get(self, request, *args, **kwargs):
		token = Token.objects.get(user=request.user)
		token.delete()
		logout(request)
		return Response({"message":"Logout successfully."},status=status.HTTP_200_OK)


class LoginView(APIView):
	@csrf_exempt
	def post(self, request, format=None):
		_data = request.data
		email = _data.get('email', None)
		password = _data.get("password", None)

		try:
			user_instance = CounterBookUser.objects.get(email=email.lower())
			if user_instance.check_password(password):
				auth = authenticate(username=email.lower(), password=password)
				if auth:
					if Token.objects.filter(user=user_instance).exists():
						_token = Token.objects.get(user=user_instance)
						_token.delete()
						token = Token.objects.create(user=user_instance)
						login(request, auth)
						_data = GetUserSerializer(user_instance).data
						return Response({"user":_data,"message":'Success', "token":token.key}, status=status.HTTP_200_OK)
					else:
						token = Token.objects.create(user=user_instance)
						login(request, user_instance)
						_data = GetUserSerializer(user_instance).data
						return Response({"user":_data, "message":'Success', "token":token.key}, status=status.HTTP_200_OK)
				else:
					return Response({"message":'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
			else:
				return Response({"message":"Password is wrong."}, status=status.HTTP_400_BAD_REQUEST)
		except CounterBookUser.DoesNotExist:
			return Response({'message':'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

class GenerateOTP(APIView):
	def post(self, request, format=None):
		email = request.data.get('email', None)

		generate_otp = OTPAuthentication(email=email.lower())
		otp_instance = generate_otp.otp_generation()
		if (otp_instance == True):
			two_factor_instance = TwoFactorAuthentication.objects.filter(
				created_at__lte=timezone.now(),
				expired_datetime__gte=timezone.now(),
				email=email).first()
			print("created_at", two_factor_instance.created_at)
			print("expire_at", two_factor_instance.expired_datetime)
			return Response({"message":"OTP generated.", "otp":two_factor_instance.otp}, status=status.HTTP_200_OK)
		else:
			return Response({"message":"otp not generated."}, status=status.HTTP_400_BAD_REQUEST)
		


class OTPVerify(APIView):
	def post(self, request, format=None):
		otp = request.data.get('otp', None)
		email = request.data.get('email', None)
		if otp:
			otp_verify = OTPAuthentication(email=email.lower(), otp=otp)
			verification_status = otp_verify.otp_verification()
			if verification_status["status"] == True:
				return Response({"message":"Done"}, status=status.HTTP_200_OK)
			elif verification_status['status'] == False:
				return Response({"message":"Please enter a valid otp."}, status=status.HTTP_400_BAD_REQUEST)
		else:
			return Response({"message":"Please enter a valid otp."}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordEmail(APIView):
	def post(self, request, format=None):
		email = request.data.get('email', None)
		try:
			user = CounterBookUser.objects.get(email=email.lower())
			forgot_instance = ForgotPassword.objects.create(user=user)
			host = request.get_host()
			reset_link = 'http://' + str(host)+'/user/set-password/'+str(forgot_instance.reset_hash)
			mail_response = Mailer(email_id=email.lower(), subject="Here's your reset password link - Expire in 1 hour!", reset_hash=reset_link, type="reset")
			mail_response()
			return Response({"message":"Link send to your email.","hash": forgot_instance.reset_hash}, status=status.HTTP_200_OK)
		except CounterBookUser.DoesNotExist:
			return Response({"message":"User Does Not exist."}, status=status.HTTP_404_NOT_FOUND)

# class SetPassword(APIView):
# 	permission_classes = [IsAuthenticated]
# 	def get(self, request, reset_hash, format=None):
# 		try:
# 			forgot_instance = ForgotPassword.objects.get(reset_hash=reset_hash, used=False)
# 			if forgot_instance.valid_till > timezone.now():
# 				return Response({"message":"Success"}, status=status.HTTP_200_OK)
# 			else:
# 				return Response({"message":"Link Expired."}, status=status.HTTP_400_BAD_REQUEST)
# 		except ForgotPassword.DoesNotExist:
# 			return Response({"message":"Link Expired."}, status=status.HTTP_404_NOT_FOUND)


@api_view(["POST"])
def reset_password(request, reset_hash):
	try:
		forgot_instance = ForgotPassword.objects.get(reset_hash=reset_hash, used=False)
		user_instance = forgot_instance.user
		password = request.POST.get('password', None)
		confirm_password = request.POST.get("confirm_password", None)
		if password and confirm_password:
			SpecialSym =['$', '@', '#', '%', '-', '_']
			if(len(password) < 8):
				return Response({"message":"Please enter at-least minimum 8 characters."}, status=status.HTTP_400_BAD_REQUEST)
			elif (len(password) > 32):
				return Response({"message":"Password should be not be greater than 20 characters."}, status=status.HTTP_400_BAD_REQUEST)
			elif(not any(char.isdigit() for char in password)):
				return Response({"message":"Password should have at least one numeral."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char.isupper() for char in password)):
				return Response({"message":"Password should have at least one uppercase letter."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char.islower() for char in password)):
				return Response({"message":"Password should have at least one lowercase letter."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char in SpecialSym for char in password)):
				return Response({"message":"Password should have at least one of the special characters."}, status=status.HTTP_400_BAD_REQUEST)
			else:
				if password == confirm_password:
					user_instance.set_password(password)
					user_instance.save()
					forgot_instance.used=True
					forgot_instance.used_date= timezone.now()
					forgot_instance.save()
					return Response({"message":"Password reset successfully."}, status=status.HTTP_200_OK)
				else:
					return Response({"message":"Create Password and Re-password  doesn't match."}, status=status.HTTP_400_BAD_REQUEST)
		else:
			return Response({"error":"Please enter a valid password."}, status=status.HTTP_400_BAD_REQUEST)
	except ForgotPassword.DoesNotExist:
		return Response({"message":"Link Expired"}, status=status.HTTP_404_NOT_FOUND)


class ChangePassword(APIView):
	permission_classes = [IsAuthenticated]
	def post(self, request, format=None):
		current_password = request.data.get('current_password', None)
		password = request.data.get('password', None)
		confirm_password = request.data.get('confirm_password', None)
		user_instance = request.user 
		if user_instance.check_password(current_password):
			if password and confirm_password:
				if password == confirm_password:
					SpecialSym =['$', '@', '#', '%', '-', '_']
					if(len(str(password)) < 8):
						return Response({"message":"Password should be at least 8 characters."}, status=status.HTTP_400_BAD_REQUEST)
					elif (len(str(password)) > 32):
						return Response({"message":"Password should be not be greater than 20 characters."}, status=status.HTTP_400_BAD_REQUEST)
					elif(not any(char.isdigit() for char in str(password))):
						return Response({"message":"Password should have at least one numeral."}, status=status.HTTP_400_BAD_REQUEST)
					elif (not any(char.isupper() for char in str(password))):
						return Response({"message":"Password should have at least one uppercase letter."}, status=status.HTTP_400_BAD_REQUEST)
					elif (not any(char.islower() for char in str(password))):
						return Response({"message":"Password should have at least one lowercase letter."}, status=status.HTTP_400_BAD_REQUEST)
					elif (not any(char in SpecialSym for char in str(password))):
						return Response({"message":"Password should have at least one of the special characters."}, status=status.HTTP_400_BAD_REQUEST)
					else:
						user_instance.set_password(password)
						user_instance.save()
						return Response({"message":'Password changed.'}, status=status.HTTP_200_OK)
				else:
					return Response({"message":"Password and confirm password are not matched."}, status=status.HTTP_400_BAD_REQUEST)
			else:
				return Response({"message":"Please enter a valid password."}, status=status.HTTP_400_BAD_REQUEST)
		else:
			return Response({"message":"Current password wrong."}, status=status.HTTP_400_BAD_REQUEST)

class BulkOrderUpdate(ModelViewSet):
	queryset = JobOrder.objects.all()
	serializer_class = JobOrderSerializer
	permission_classes = [IsAuthenticated]

	#this api is used to change the order status for bulk order
	#end point: /api/order/1,2/complete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def complete(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.status = "Completed"
			order.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/order/1,2/active/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def active(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.status = "Active"
			order.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/order/1,2/pending/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def pending(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.status = "Pending"
			order.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/order/1,2/pending_pickup/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def pending_pickup(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.status = "PendingPickup"
			order.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/order/1,2/delete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def delete(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.is_delete = True
			order.save()
			print("data deleted")
		return Response({"message":"Order deleted successfully."}, status=status.HTTP_200_OK)
	#end point: /api/order/1,2/permanent_delete/
	@action(detail=True, methods=['DELETE'], permission_classes=[IsAuthenticated,])
	def permanent_delete(self, request, pk=None):
		for i in pk.split(','):
			order_instance = JobOrder.objects.get(id=i)
			order_instance.delete()
		return Response({"message":"Orders are permanently deleted."}, status=status.HTTP_200_OK)
	

class BulkDeliveryUpdate(ModelViewSet):
	queryset = Delivery.objects.all()
	serializer_class = DeliverySerializer
	permission_classes = [IsAuthenticated]

	#this api is used to change the delivery status for bulk delivery
	#end point: /api/delivery/1,2/complete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def complete(self, request, pk=None):
		for i in pk.split(','):
			delivery = Delivery.objects.get(id=i)
			delivery.status = "Completed"
			delivery.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/delivery/1,2/active/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def active(self, request, pk=None):
		for i in pk.split(','):
			delivery = Delivery.objects.get(id=i)
			delivery.status = "Active"
			delivery.save()
		return Response({"message":"Status changed succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/delivery/1,2/delete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def delete(self, request, pk=None):
		for i in pk.split(','):
			delivery = Delivery.objects.get(id=i)
			delivery.is_delete = True
			delivery.save()
		return Response({"message":"Delivery deleted succesfully."}, status=status.HTTP_200_OK)

	#end point: /api/delivery/1,2/delete/
	@action(detail=True, methods=['DELETE'], permission_classes=[IsAuthenticated,])
	def permanent_delete(self, request, pk=None):
		for i in pk.split(','):
			delivery_instance = Delivery.objects.get(id=i)
			delivery_instance.delete()
		return Response({"message":"Deliveries are deleted."}, status=status.HTTP_200_OK)

class UndoOrderUpdate(ModelViewSet):
	queryset = JobOrder.objects.all()
	serializer_class = JobOrderSerializer
	permission_classes = [IsAuthenticated]

	#end point: /api/order-undo/1,2/delete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def delete(self, request, pk=None):
		for i in pk.split(','):
			order = JobOrder.objects.get(id=i)
			order.is_delete = False
			order.save()
		return Response({"message":"Success"},status=status.HTTP_200_OK)

class UndoDeliveryUpdate(ModelViewSet):
	queryset = Delivery.objects.all()
	serializer_class = DeliverySerializer
	permission_classes = [IsAuthenticated]

	#end point: /api/delivery-undo/1,2/delete/
	@action(detail=True, methods=['PATCH'], permission_classes=[IsAuthenticated,])
	def delete(self, request, pk=None):
		for i in pk.split(','):
			delivery = Delivery.objects.get(id=i)
			delivery.is_delete = False
			delivery.save()
		return Response({"message":"Success"}, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notification(request):
	user_instance = request.user
	if user_instance.is_push_comment and user_instance.is_push_reminder and user_instance.is_push_edit:
		data = Notification.objects.filter(created_by=user_instance).order_by('-id')
	elif user_instance.is_push_comment and user_instance.is_push_reminder:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type="Comment") |Q(type="Reminder") |Q(type="Create")).order_by("-id")
	elif user_instance.is_push_comment and user_instance.is_push_edit:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type="Comment") |Q(type="Edit") |Q(type="Create")).order_by("-id")
	elif user_instance.is_push_reminder and user_instance.is_push_edit:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type="Reminder") |Q(type="Edit") |Q(type="Create")).order_by("-id")
	elif user_instance.is_push_reminder:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type="Reminder") |Q(type="Create")).order_by("-id")
	elif user_instance.is_push_comment:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type='Comment')|Q(type="Create")).order_by("-id")
	elif user_instance.is_push_edit:
		data = Notification.objects.filter(created_by=user_instance).filter(Q(type='Edit')|Q(type="Create")).order_by("-id")
	else:
		data = Notification.objects.filter(created_by=user_instance, type="Create").order_by("-id")

	return Response({"data":NotificationSerializer(data, many=True).data, "total_count":data.count(), "read_count":data.filter(is_read=True).count(), "unread_count":data.filter(is_read=False).count()}, status=status.HTTP_200_OK)
	


class NotificationSettings(ModelViewSet):

	serializer_class = NotificationSettingSerializer
	permission_classes =[IsAuthenticated]
	http_method_names = ['get', 'put', 'patch']

	def get_queryset(self):
		return CounterBookUser.objects.filter(email=self.request.user)

	def partial_update(self, request, pk=None):
		user_instance = CounterBookUser.objects.get(id=pk) 
		data = request.data
		user_instance.is_email_reminder = data.get('is_email_reminder')
		user_instance.is_email_edit = data.get('is_email_edit')
		user_instance.is_email_comment = data.get('is_email_comment')
		user_instance.is_push_reminder = data.get('is_push_reminder')
		user_instance.is_push_comment = data.get('is_push_comment')
		user_instance.is_push_edit = data.get('is_push_edit')
		user_instance.save()
		data = CounterBookUserSerializer(user_instance).data
		return Response(data, status=status.HTTP_200_OK)

class JobOrderFilter(ModelViewSet):
	queryset = JobOrder.objects.all()
	serializer_class = JobOrderSerializer
	permission_classes = [IsAuthenticated]
	http_method_names = ['get']

	def list(self, request, *args, **kwargs):
		_type = self.request.query_params.get('type', None)
		_status = self.request.query_params.get('status', None)
		_date = self.request.query_params.get('date', None)
		members = CounterBookUser.objects.filter(members__id=self.request.user.id)
		if _date:
			starting_date = _date.split('/')[0]
			end_date = _date.split('/')[1]
		if _type == 'Order':

			if _type and _status and _date:
				_data = self.serializer_class(JobOrder.objects.filter(status=_status, is_delivered=False, created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _type and _status:
				_data = self.serializer_class(JobOrder.objects.filter(status=_status, is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _status and _date:
				_data = self.serializer_class(JobOrder.objects.filter(status=_status, created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _type:
				_data = self.serializer_class(JobOrder.objects.filter(is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _status:
				_data =self.serializer_class(JobOrder.objects.filter(status=_status).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _date:
				_data = self.serializer_class(JobOrder.objects.filter(created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			else:
				_data = {}
				return Response({"data":_data})
		else:

			if _type and _status and _date:
				_data = DeliverySerializer(Delivery.objects.filter(status=_status, is_delivered=False, created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _type and _status:
				_data = DeliverySerializer(Delivery.objects.filter(status=_status, is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _status and _date:
				_data = DeliverySerializer(Delivery.objects.filter(status=_status, created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _type:
				_data = DeliverySerializer(Delivery.objects.filter(is_delivered=False).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _status:
				_data =DeliverySerializer(Delivery.objects.filter(status=_status).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			elif _date:
				_data = DeliverySerializer(Delivery.objects.filter(created_at__gte=starting_date, created_at__lte=end_date).filter(Q(created_by=self.request.user)|Q(created_by=self.request.user.added_by)|Q(created_by__in=members)), many=True).data
				return Response({"data":_data})
			else:
				_data = {}
				return Response({"data":_data})

@api_view(['GET'])
def get_staff_users(request):
	staff_users = CounterBookUser.objects.filter(is_staff=True, is_active=True)
	staff_data = CounterBookUserSerializer(staff_users, many=True).data
	return Response(staff_data, status=status.HTTP_200_OK)

@api_view(['GET'])
def get_admin_users(request):
	admin_users = CounterBookUser.objects.filter(is_admin=True, is_active=True)
	admin_data = CounterBookUserSerializer(admin_users, many=True).data
	return Response(admin_data, status=status.HTTP_200_OK)


@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def dashboard(request):
	today_date = timezone.now().date()
	today_order = JobOrder.objects.all().order_by("-created_at")
	today_delivery = Delivery.objects.filter(created_at=today_date)
	today_sales = JobOrder.objects.filter(created_at=today_date).count() + today_delivery.count()
	total_sales = JobOrder.objects.all().count() + Delivery.objects.all().count()
	pre_orders = JobOrder.objects.filter(created_at__lt= today_date).count()
	pre_delivery = Delivery.objects.filter(created_at__lt=today_date).count()
	pre_total = pre_orders+ pre_delivery
	aggregate_time_order = JobOrder.objects.aggregate(Min('created_at'), Max('created_at')) 
	aggregate_time_delivery = Delivery.objects.aggregate(Min('created_at'), Max('created_at')) 

	if aggregate_time_order["created_at__max"] > aggregate_time_delivery['created_at__max']:
		starting_date = aggregate_time_order['created_at__max']
	else:
		starting_date = aggregate_time_delivery['created_at__max']
	if aggregate_time_order['created_at__min'] > aggregate_time_delivery['created_at__min']:
		ending_date = aggregate_time_delivery['created_at__min']
	else:
		ending_date = aggregate_time_order['created_at__min']
	total_days = (starting_date - ending_date).days

	yesterday = timezone.now().date() - timezone.timedelta(days=1)
	yesterday_sales = JobOrder.objects.filter(created_at=yesterday).count() + Delivery.objects.filter(created_at=yesterday).count()
	if pre_total == 0:
		total_percentage = math.floor(today_sales *100)
	else:
		total_percentage = math.floor((today_sales/pre_total)*100)
	if yesterday_sales ==0:
		today_percentage = math.floor(today_sales*100)
	else:
		today_percentage = math.floor((today_sales/yesterday_sales)*100)
	average_sales = math.floor(total_sales/total_days)
	pre_average = pre_total/(total_days-1)
	if average_sales == 0:
		average_percentage= 0
	else:
		average_percentage = math.floor(((average_sales-pre_average)/pre_average)*100)
	
	return Response({'today_order':OrderDetailSerializer(today_order[0:5], many=True).data, 'today_sales':today_sales,
		'total_sales':total_sales, 'total_percentage':total_percentage, "average_sales":average_sales, 
		'average_percentage':average_percentage, 'today_percentage':today_percentage}, status=status.HTTP_200_OK)

@api_view(['POST'])
def add_user(request, id):
	_data = request.data
	email_lower = _data['email'].lower()
	_data["added_by"] = id
	_data["email"] = email_lower
	if CounterBookUser.objects.filter(email=request.data.get("email").lower()).exists():
		return Response({"message":"Email already exists."}, status=status.HTTP_400_BAD_REQUEST)
	else:
		serializer = CounterBookUserSerializer(data=_data)
		if serializer.is_valid():
			SpecialSym =['$', '@', '#', '%', '-', '_']
			password = _data["password"]
			if(len(str(password)) < 8):
				return Response({"message":"Password should be at least 8 characters."}, status=status.HTTP_400_BAD_REQUEST)
			elif (len(str(password)) > 32):
				return Response({"message":"Password should be not be greater than 20 characters."}, status=status.HTTP_400_BAD_REQUEST)
			elif(not any(char.isdigit() for char in str(password))):
				return Response({"message":"Password should have at least one numeral."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char.isupper() for char in str(password))):
				return Response({"message":"Password should have at least one uppercase letter."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char.islower() for char in str(password))):
				return Response({"message":"Password should have at least one lowercase letter."}, status=status.HTTP_400_BAD_REQUEST)
			elif (not any(char in SpecialSym for char in str(password))):
				return Response({"message":"Password should have at least one of the special characters."}, status=status.HTTP_400_BAD_REQUEST)
			else:
				serializer.save()
				user = CounterBookUser.objects.get(id=serializer.data["id"])
				user_instance = CounterBookUser.objects.get(id=id)
				user_instance.members.add(user)
				user_instance.save()
				user = CounterBookUser.objects.get(id=serializer.data["id"])
				user.set_password(request.data["password"])
				user.save()
				user.business_name = user_instance.business_name
				user.business_address = user_instance.business_address
				user.business_email = user_instance.business_email
				user.business_phone = user_instance.business_phone
				user.logo = user_instance.logo
				user.is_completed=True
				user.is_picture =True
				user.is_email_verified=True
				user.save()
				return Response(GetUserSerializer(user_instance).data, status=status.HTTP_200_OK)
		return Response(getFirstError(serializer.errors), status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def remove_user(request, id):
	user = CounterBookUser.objects.get(id=id)
	user_instance = CounterBookUser.objects.get(id=request.data['user_id'])
	user.members.remove(user_instance)
	user.save()
	return Response(GetUserSerializer(user).data, status=status.HTTP_200_OK)

@api_view(["POST"])
def order_upload(request, id):
	order = JobOrder.objects.get(id=id)
	serializer = UplaodAttachmentSerializer(data=request.data)
	if serializer.is_valid():
		serializer.save()
		order.attachment.add(serializer.data["id"])
		order.save()
		return Response({"data":serializer.data}, status=status.HTTP_200_OK)


@api_view(["POST"])
def delivery_upload(request, id):
	delivery = Delivery.objects.get(id=id)
	serializer = UplaodAttachmentSerializer(data=request.data)
	if serializer.is_valid():
		serializer.save()
		delivery.attachment.add(serializer.data["id"])
		delivery.save()
		return Response({"data":serializer.data}, status=status.HTTP_200_OK)

@api_view(['POST'])
def complete_profile(request):
	user_instance = CounterBookUser.objects.get(id=request.data["id"])
	user_instance.is_completed =True
	user_instance.save()
	if Token.objects.filter(user=user_instance).exists():
		_token = Token.objects.get(user=user_instance)
		_token.delete()
		new_token = Token.objects.create(user=user_instance)
	else:
		new_token = Token.objects.create(user=user_instance)

	return Response({"user":GetUserSerializer(user_instance).data, "token":new_token.key, "message":"Success"}, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def driver_list(request):
	members = []
	users = []
	if request.user.added_by:
		users = CounterBookUser.objects.filter(is_staff=True).filter(Q(added_by=request.user)|Q(added_by=request.user.added_by))
	else:
		users = CounterBookUser.objects.filter(is_staff=True).filter(added_by=request.user)
	# driver_user = CounterBookUser.objects.filter(added_by=request.user)
	for user in users:
		if user != request.user:
			members.append(user)
	data = DriverUserSerializer(members, many=True).data
	return Response({"driverList":data}, status=status.HTTP_200_OK)

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_driver(request, id):
	delivery_instance = Delivery.objects.get(id=id)
	driver_id = request.data["driver_id"]
	user_instance = CounterBookUser.objects.get(id=driver_id)
	delivery_instance.driver = user_instance
	delivery_instance.save()
	data = DeliverySerializer(delivery_instance).data
	return Response({"data":data}, status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_trashed_orders(request):
	members = []
	if request.user.added_by:
		members = CounterBookUser.objects.filter(Q(added_by=request.user)|Q(added_by=request.user.added_by))
	else:
		members = CounterBookUser.objects.filter(Q(added_by=request.user))

	orders = JobOrder.objects.filter(is_delete=True, is_delivered=False).filter(Q(created_by=request.user)|Q(created_by=request.user.added_by)|Q(created_by__in=members))
	data = OrderDetailSerializer(orders, many=True).data
	return Response({'data':data}, status=status.HTTP_200_OK)
	

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_trashed_deliveries(request):
	members = []
	if request.user.added_by:
		members = CounterBookUser.objects.filter(Q(added_by=request.user)|Q(added_by=request.user.added_by))
	else:
		members = CounterBookUser.objects.filter(Q(added_by=request.user))

	deliveries = Delivery.objects.filter(is_delete=True, is_delivered=False).filter(Q(created_by=request.user)|Q(created_by=request.user.added_by)|Q(created_by__in=members))
	data = DeliveryDetailSerializer(deliveries, many=True).data
	return Response({'data':data}, status=status.HTTP_200_OK)

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def read_notification(request, id):
	notification = Notification.objects.get(id=id)
	notification.is_read=True
	notification.save()
	return Response({"message":"Read"}, status=status.HTTP_200_OK)