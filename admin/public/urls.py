from django.conf.urls import patterns, include, url
from public import views

urlpatterns = patterns('',
  url(r'^document/(?P<docid>.+?)/$', views.document, name='document'),
  url(r'^raw_document/(?P<docid>.+?)/$', views.raw_document, name='raw_document'),
  url(r'^student/(?P<student_id>.+?)/$', views.student, name='student'),
)