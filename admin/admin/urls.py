from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.auth import views as auth_views

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', auth_views.login),
    url(r'^secure/', include('certchain.urls', namespace='certchain')),
)
