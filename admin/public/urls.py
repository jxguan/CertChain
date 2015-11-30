from django.conf.urls import patterns, include, url
from public import views

urlpatterns = patterns('',
  url(r'^transcript/(?P<docid>.+?)/$', views.transcript, name='transcript'),
  url(r'^diploma/(?P<docid>.+?)/$', views.diploma, name='diploma'),
  url(r'^raw_document/(?P<docid>.+?)/$', views.raw_document, name='raw_document'),
  url(r'^raw_block/(?P<block_height>.+?)/$', views.raw_block, name='raw_block'),
  url(r'^student/(?P<student_id>.+?)/$', views.student, name='student'),
)