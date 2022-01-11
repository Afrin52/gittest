import os
from django.http.response import HttpResponse
from django.shortcuts import render, redirect
from django.views import View
from counterbookuser.models import Comment, Delivery, ForgotPassword, JobOrder
from django.utils import timezone
import re
from api.serializers import DeliveryDetailSerializer
# import pydf
from django.template.loader import get_template
from django.conf import settings
from django.shortcuts import get_object_or_404, render


class SetPassword(View):
	template_name = 'set_password.html'
	def get(self, request, reset_hash, *args, **kwargs):
		
		try:
			forgot_instance = ForgotPassword.objects.get(reset_hash=reset_hash, used=False)
			if forgot_instance.valid_till > timezone.now():
				return render(request, self.template_name, {"reset_hash":reset_hash})
			else:
				return render(request, self.template_name, {"link":"Link Expired."})
		except ForgotPassword.DoesNotExist:
			return render(request, self.template_name, {"link":"Link Expired."})

	# def post(self, request, reset_hash, *args, **kwargs):
	# 	try:
	# 		forgot_instance = ForgotPassword.objects.get(reset_hash=reset_hash, used=False)
	# 		user_instance = forgot_instance.user
	# 		password = request.POST.get('password', None)
	# 		confirm_password = request.POST.get("confirm_password", None)
	# 		print("passs", password)
	# 		if password == '':
	# 			return render(request, self.template_name, {"password":"Please enter New Password"})
	# 		if confirm_password == '':
	# 			return render(request, self.template_name, {"confirm_password":"Please enter confirm password."})
	# 		if password and confirm_password:
	# 			SpecialSym =['$', '@', '#', '%', '-', '_']
	# 			if(len(password) < 8):
	# 				return render(request, self.template_name, {"min":"Please enter at-least minimum 8 characters."})
	# 			elif (len(password) > 32):
	# 				return render(request, self.template_name, {"max":"Password should be not be greater than 20 characters."})
	# 			elif(not any(char.isdigit() for char in password)):
	# 				return render(request, self.template_name, {"digit":"Password should have at least one numeral."})
	# 			elif (not any(char.isupper() for char in password)):
	# 				return render(request, self.template_name, {"upper":"Password should have at least one uppercase letter."})
	# 			elif (not any(char.islower() for char in password)):
	# 				return render(request, self.template_name, {"lower":"Password should have at least one lowercase letter."})
	# 			elif (not any(char in SpecialSym for char in password)):
	# 				return render(request, self.template_name, {"special":"Password should have at least one of the special characters."})
	# 			else:
	# 				if password == confirm_password:
	# 					user_instance.set_password(password)
	# 					user_instance.save()
	# 					forgot_instance.used=True
	# 					forgot_instance.used_date= timezone.now()
	# 					forgot_instance.save()
	# 					return redirect('/user/verified')
	# 				else:
	# 					return render(request, self.template_name, {"pcnm":"Create Password and Re-password  doesn't match."})
	# 		else:
	# 			return render(request, self.template_name, {"error":"Please enter a valid password.",})
	# 	except ForgotPassword.DoesNotExist:
	# 		return render(request, self.template_name, {"link":"Link Expired."})


def Verifid(request):
	return render(request, 'verified.html')

def delivery_detail(request):
	data = Delivery.objects.get(id=1)
	comment = Comment.objects.filter(delivery=data)
	return render(request, 'delivery.html', {'data': data, 'comment': comment })

def order_detail(request):
	data = JobOrder.objects.get(id=1)
	comment = Comment.objects.filter(order=data)
	return render(request, 'order.html', {'data': data, 'comment': comment })
# ==================================================================================

# from fcm_django.models import FCMDevice
# # from counterbook.settings import FCM_SERVER_KEY
# data = {
#          "name": "HORN OK PLEASE!",
#          "days": 3,
#          "country": "United States"
#        }
# def send_notification(user_ids=["1","2","3"],
#                   title="It's now or never: Horn Ok is back!",
#                   message="Book now to get 50% off!",
#                   data=data):
# 	print("hello")
# 	try:
# 		device = FCMDevice.objects.filter(user__in=user_ids).first()
# 		result = device.send_message(title=title,body=message,
# 							data=data,sound=True)
# 		return HttpResponse("sent")
# 	except:
# 		pass
# from fcm_django.models import FCMDevice
# from firebase_admin.messaging import Message, Notification
# def send_notification(request):
# 	Message(
# 		notification=Notification(title="title", body="text", image="url"),
# 		topic="Optional topic parameter: Whatever you want",
# 	)
# 	print("hello")
# 	# FCMDevice.objects.send_message(Message(...), False, ["registration_ids"])

# 	# You can still use .filter() or any methods that return QuerySet (from the chain)
# 	device = FCMDevice.objects.all().first()
# 	# send_message parameters include: message, dry_run, app
# 	device.send_message(Message(data = {
#          "name": "HORN OK PLEASE!",
#          "days": 3,
#          "country": "United States"
#        }))

# from pyfcm import FCMNotification
import requests 
import json

def send(request):
	registration = ["AAAA8lRYGGg:APA91bHJXPJbe-5MN1O4Cf3pEDikOpYrgrX4UxvS-DeDcPndaseh9_51fWuaqbkPKgOIrpCboDNpBn6T5jSxU6DwKtLhdzim0C5w9Xqh1nvdfvAr4_2iqNtcsEhZmOOgoNtbEYQpoUph"]
	sent=send_notification(registration,"It's now or never: Horn Ok is back!", 'Book now to get 50% off!' )
	return HttpResponse("sent")

def send_notification(registration_ids, message_title, message_decs):
	api_key="AAAAMvKd27A:APA91bHbz7H1GQu3tZ0YmQhx5l-U30Lo8hx3C6aRl4D82iA_qNCc_hb0l8qfUwiBGS7pSFlWvflrnIONNxFGu3bVeMIPvrjoJL6595BCuCHC-qSXqObD85ntOGgFOKSz1ZQbtGa1SAMX"
	url = "http://counter.com"

	headers = {
	'Authorization': 'key= '+api_key,
	'Content-Type': 'application/json; UTF-8' 
	}
	payload = {
		"registration_ids" :registration_ids,
		"priority": "high",
		"notification" : {
			"body": message_decs,
			"title": message_title
		}
	}
	
	result = requests.post(url, data=json.dumps(payload), headers=headers)
	print(result.json)

def index(request):
	return render(request, 'index.html')



def showfirebasejs(request):
	data='importScripts("https://www.gstatic.com/firebasejs/9.6.1/firebase-app.js");' \
		'importScripts("https://www.gstatic.com/firebasejs/9.6.1/firebase-messaging.js");' \
		'var firebaseConfig = {' \
		'	apiKey: "AIzaSyDtbmlJ19oBUOm5dwpzPmtqycs6SrN70eY",' \
		'	authDomain: "bookcounter-c2b0f.firebaseapp.com",' \
		'	projectId: "bookcounter-c2b0f",' \
		'	databaseURL: "https://console.firebase.google.com/project/bookcounter-c2b0f/overview",' \
		'	storageBucket: "bookcounter-c2b0f.appspot.com",' \
		'	messagingSenderId: "218818796464",' \
		'	appId: "1:218818796464:web:76690912bb7199c6595475",' \
		'	measurementId:"G-PTFEEJXB3J",' \
		'	};' \
		'firebase.initializeApp(firebaseConfig);' \
		'const messaging = firebase.messaging();' \
		'messaging.setBackgroundMessageHandler(function(payload){' \
		'	console.log(payload);' \
		'	const notification = JSON.parse(payload);' \
		'	const notificationOptions={' \
		'		body:notification.body,' \
		'		icon:notification.icon,' \
		'	};' \
		'})' \
		'return self.registration.showNotification(payload.notification.title,notificationOptions)'
	return HttpResponse(data, content_type='text/javascript', charset="utf-8")
