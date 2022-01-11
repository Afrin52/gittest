from django.urls import path
from api import views
from rest_framework.routers import DefaultRouter

routers = DefaultRouter()

routers.register('driver', views.DriverViewSet, basename='driver')
routers.register('jobs', views.JobOrderViewSet, basename='jobs')
# routers.register('upload', views.UploadAttachmentViewSet, basename='upload')
routers.register('order', views.BulkOrderUpdate, basename='order')
routers.register('order-undo', views.UndoOrderUpdate, basename='order-undo')
routers.register('order-detail', views.OrderDetailViewSet, basename='order-detail')
# routers.register('comments', views.CommentModelViewSet, basename='comments')
routers.register('order-filter', views.OrderFilter, basename='order-filter')
routers.register('order-history', views.OrderHistoryViewSet, basename='order-history')
routers.register('team-members', views.TeamMembersViewSet, basename='team-members')
# routers.register('user', views.CounterBookUserViewSet, basename='add-user')
routers.register('select-driver', views.SelectDriverViewSet, basename='select-driver')
routers.register('create-user', views.CreateUser, basename='create-user')
routers.register('settings', views.NotificationSettings, basename='settings')
routers.register('filter', views.JobOrderFilter, basename='filter')
routers.register('delivery', views.BulkDeliveryUpdate, basename='delivery')
routers.register('delivery-undo', views.UndoDeliveryUpdate, basename='delivery-undo')
routers.register('deliveries', views.DeliveryViewSet, basename='deliveries')
routers.register('delivery-detail', views.DeliveryDetailViewSet, basename='delivery-detail')
routers.register('delivery-filter', views.DeliveryFilter, basename='delivery-filter')

urlpatterns = [
    path('logout/', views.Logout.as_view()),
    path('login/', views.LoginView.as_view()),
    path("user/<int:id>/", views.get_user),
    path('generate-otp/', views.GenerateOTP.as_view()),
    path('verify-otp/', views.OTPVerify.as_view()),
    path('forgot-password/', views.ForgotPasswordEmail.as_view()),
    path('change-password/', views.ChangePassword.as_view()),
    path("staff-users/", views.get_staff_users),
    path("admin-users/", views.get_admin_users),
    path('dashboard/', views.dashboard),
    path("add-user/<int:id>/", views.add_user),
    path("remove-user/<int:id>/", views.remove_user),
    path("update-user/<int:id>/", views.update_user),
    path("complete-profile/", views.complete_profile),
    path("order_upload/<int:id>/", views.order_upload),
    path("delivery_upload/<int:id>/", views.delivery_upload),
    path("set-password/<str:reset_hash>/", views.reset_password),
    path("driver-list/", views.driver_list),
    path("add-driver/<int:id>/", views.add_driver),
    path("get_order/<int:id>/", views.order_detail),
    path("get_delivery/<int:id>/", views.delivery_detail),
    path("comments/", views.create_comment),
    path("get_trashed_orders/", views.get_trashed_orders),
    path("get_trashed_deliveries/", views.get_trashed_deliveries),
    path("update_comment/<int:id>/", views.update_comment),
    path('delete_comment/<int:id>/', views.delete_comment),
    path("read_notification/<int:id>/", views.read_notification),
    path("notification/", views.notification),
    path("send/", views.send),

]

urlpatterns += routers.urls