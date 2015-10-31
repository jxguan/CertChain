from django.conf.urls import patterns, include, url
from django.contrib import admin
from certchain import views

urlpatterns = patterns('',
  url(r'^overview/$', views.overview, name='overview'),
  url(r'^approve_peer_request/$', views.approve_peer_request, name='approve_peer_request'),
  url(r'^certify/$', views.certify, name='certify'),
  url(r'^manage_certifications/$', views.manage_certifications, name='manage_certifications'),
  url(r'^trust_institution/$', views.trust_institution, name='trust_institution'),
  url(r'^untrust_institution/$', views.untrust_institution, name='untrust_institution'),
  url(r'^certify_diploma/$', views.certify_diploma, name='certify_diploma'),
  url(r'^revoke_diploma/$', views.revoke_diploma, name='revoke_diploma'),
)