import requests, json
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.http import Http404


def certify(request):
  return render(request, 'certify/certify.html', {})

def verify_json(request, raw_data, json):
  type = 'diploma' if (json['contents'].get('degree')) else 'transcript'
  return render(request, 'certify/'+ type + '.html',
        {'doc' : json['contents'], 'raw_data': raw_data})

def certify_document(request):
  if (request.method == 'POST'):
    if (request.POST.get('document_url')):
      try:
        resp = requests.get(request.POST['document_url'])
        return verify_json(request, resp.text, resp.json())
      except Exception as ex:
        messages.error(request, 'Invalid Url provided. Please try again.')
        return redirect('/')
    elif (request.FILES.get('document_file')):
      try:
        file = request.FILES['document_file']
        raw_data = file.read()
        jsonData = json.loads(raw_data)
        return verify_json(request, raw_data, jsonData)
      except Exception as ex:
        messages.error(request, 'Invalid document file provided. Please try \
        again.')
        return redirect('/')
  raise Http404
