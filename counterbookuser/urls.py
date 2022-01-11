from django.urls import path, include
from counterbookuser import views
urlpatterns = [
	path("set-password/<str:reset_hash>", views.SetPassword.as_view()),
	path("verified", views.Verifid),
	path("delivery/", views.delivery_detail),
	path("order/", views.order_detail),
	# path("index/", views.index),
	# path("send/", views.send),

] 
