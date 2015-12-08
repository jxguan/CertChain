from django.conf.urls import patterns, include, url
from student import views

urlpatterns = patterns('',
  url(r'^login/$', views.login, name='login'),
  url(r'^logout/$', views.logout, name='logout'),
  url(r'^documents/', views.documents, name='documents'),
)
