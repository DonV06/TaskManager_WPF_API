from django.contrib import admin
from django.urls import path
from API.views import DownloadPublicKeyView, APIRequest

urlpatterns = [
    path('admin/', admin.site.urls),
    path('download_public_key/', DownloadPublicKeyView.as_view(), name='download_public_key'),
    path('api_request/', APIRequest, name='api_request'),
]
