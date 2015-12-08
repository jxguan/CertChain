from django.conf.urls import patterns, include, url
from certify import views

urlpatterns = patterns('',
  url(r'^$', views.certify, name='certify'),
  url(r'^certify_document/$', views.certify_document, name='certify_document')
)
