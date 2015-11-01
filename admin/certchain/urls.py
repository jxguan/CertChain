from django.conf.urls import patterns, include, url
from django.contrib import admin
from certchain import views

urlpatterns = patterns('',
  url(r'^overview/$', views.overview, name='overview'),
  url(r'^approve_peer_request/$', views.approve_peer_request, name='approve_peer_request'),
  url(r'^request_peer/$', views.request_peer, name='request_peer'),
  url(r'^end_peering/$', views.end_peering, name='end_peering'),
  url(r'^certify/$', views.certify, name='certify'),
  url(r'^manage_certifications/$', views.manage_certifications, name='manage_certifications'),
  url(r'^trust_institution/$', views.trust_institution, name='trust_institution'),
  url(r'^untrust_institution/$', views.untrust_institution, name='untrust_institution'),
  url(r'^certify_diploma/$', views.certify_diploma, name='certify_diploma'),
  url(r'^certify_transcript/$', views.certify_transcript, name='certify_transcript'),
  url(r'^revoke_diploma/$', views.revoke_diploma, name='revoke_diploma'),
)