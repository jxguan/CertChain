from django.conf.urls import patterns, include, url
from public import views

urlpatterns = patterns('',
  url(r'^document/(?P<docid>.+?)/$', views.document, name='document'),
  url(r'^student/(?P<studentid>.+?)/$', views.student, name='student'),
)