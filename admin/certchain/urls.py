from django.conf.urls import patterns, include, url
from django.contrib import admin
from certchain import views

urlpatterns = patterns('',
  url(r'^overview/$', views.overview, name='overview'),
  url(r'^add_node/$', views.add_node, name='add_node'),
  url(r'^remove_node/$', views.remove_node, name='remove_node'),
  url(r'^approve_peer_request/$', views.approve_peer_request, name='approve_peer_request'),
  url(r'^request_peer/$', views.request_peer, name='request_peer'),
  url(r'^end_peering/$', views.end_peering, name='end_peering'),
  url(r'^certify/$', views.certify, name='certify'),
  url(r'^manage_certifications/$', views.manage_certifications, name='manage_certifications'),
  url(r'^certify_diploma/$', views.certify_diploma, name='certify_diploma'),
  url(r'^certify_transcript/$', views.certify_transcript, name='certify_transcript'),
  url(r'^revoke_document/$', views.revoke_document, name='revoke_document'),
)