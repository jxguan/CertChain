import requests, json, base64
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.urlresolvers import reverse
from certchain.shared import create_rpc_url
from collections import defaultdict
from django.http import HttpResponse
import datetime

import logging
logger = logging.getLogger('certchain')

def get_document(request, docid, type):
  try:
      resp = requests.get(create_rpc_url('/document/' + docid))
      json = resp.json()
      return render(request, 'public/'+ type + '.html',
        {'docid' : docid, 'doc' : json['contents'], 'raw_data': resp.text})
  except Exception as ex:
    messages.error(request, 'Unable to retrieve ' + type + ' at this time: ' + str(ex))
    return redirect(reverse('certchain:manage_certifications'))

def diploma(request, docid):
  return get_document(request, docid, 'diploma')

def transcript(request, docid):
  return get_document(request, docid, 'transcript')

# Allows public users to see raw JSON data via link;
# we cannot link directly to the RPC port as that is
# not intended to be publicly accessible.
def raw_document(request, docid):
  resp = requests.get(create_rpc_url('/document/' + docid))
  return HttpResponse(resp.text, content_type='application/json')

def raw_block(request, block_height):
  resp = requests.get(create_rpc_url('/block/' + block_height))
  return HttpResponse(resp.text, content_type='application/json')

def student(request, student_id):
  try:
    resp = requests.get(create_rpc_url('/certifications_by_student_id/' + student_id))
    certs_by_type = defaultdict(list)
    for c in resp.json():
      certs_by_type[c['doc_type']].append(c)
    return render(request, 'public/student.html',\
      {'certs_by_type' : certs_by_type.iteritems(),
       'student_id': student_id,
      })
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time: ' + str(ex))
    return render(request, 'public/student.html', {'student_id': student_id})