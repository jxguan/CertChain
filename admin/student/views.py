from django.shortcuts import render, redirect
import requests
from django.contrib import messages
from django.http import HttpResponse
from django import forms
from collections import defaultdict
from certchain.shared import create_rpc_url

class LoginForm(forms.Form):
  studentId = forms.CharField(label='Student ID', max_length=100)
  password = forms.CharField(widget=forms.PasswordInput)

def login(request):
  if (request.session.get('studentId')):
    return redirect('/student/documents')
  if request.method == 'POST':
    form = LoginForm(request.POST)
    if form.is_valid():
      if (request.POST['password'] == request.POST['studentId']):
        request.session['studentId'] = request.POST['studentId'];
        return redirect('/student/documents')
      else:
        form.add_error('password',
        'Invalid student ID and password combination')
  else:
    form = LoginForm()
  return render(request, 'student/login.html', {'form': form})

def logout(request):
  request.session.clear()
  return redirect('/student/login')

def documents(request):
  studentId = request.session.get('studentId')
  if (studentId):
    try:
      resp = requests.get(create_rpc_url('/certifications_by_student_id/' +
          studentId))
      certs_by_type = defaultdict(list)
      for c in resp.json():
        print c['doc_id']
        certs_by_type[c['doc_type']].append(c)
      print 'yoo'
      return render(request, 'student/documents.html',\
      {'certs_by_type' : certs_by_type.iteritems(),
       'studentId': studentId,
      })
    except Exception as ex:
      messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time: ' + str(ex))
      return render(request, 'student/documents.html', {'studentId': studentId})
  else:
    return HttpResponse("Yooo", content_type='text/plain')


