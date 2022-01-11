
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from counterbookuser.views import *
from django.views.generic import TemplateView
from counterbookuser import views
urlpatterns = [
    # path("firebase-messaging-sw.js/",
    #     TemplateView.as_view(
    #         template_name="firebase-messaging-sw.js",
    #         content_type="application/javascript",
    #     ),
    #     name="firebase-messaging-sw.js"
    # ),
   
    
	path('jet/', include('jet.urls', 'jet')),
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('user/', include('counterbookuser.urls')),
    # path('firebase-messaging-sw.js/', showfirebasejs, name="firebase-messaging-sw.js"),
    path('', index),

     
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) +static(
	settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

