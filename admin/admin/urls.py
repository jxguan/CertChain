from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.auth import views as auth_views
from certchain import views

urlpatterns = patterns('',
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', auth_views.login),
    url(r'^logout/', auth_views.logout),
    url(r'^secure/', include('certchain.urls', namespace='certchain')),
    url(r'^viewer$', views.viewer, name='viewer'),
)
