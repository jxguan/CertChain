from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.auth import views as auth_views

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', auth_views.login),
    url(r'^logout/', auth_views.logout),
    url(r'^secure/', include('certchain.urls', namespace='certchain')),
    url(r'^public/', include('public.urls', namespace='public')),
    url(r'^student/', include('student.urls', namespace='student')),
)
