from django.conf.urls import patterns, include, url
from django.contrib import admin
from certchain import views

urlpatterns = patterns('',
  url(r'^overview$', views.overview, name='overview'),
  url(r'^trust_institution$', views.trust_institution, name='trust_institution'),
)