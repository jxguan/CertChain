from django.conf.urls import include, url, patterns
from django.contrib import admin
from certify import views

urlpatterns = [
  url(r'^$', views.certify),
  url(r'^certify/', include('certify.urls', namespace="certify")),
  url(r'^admin/', include(admin.site.urls)),
]
