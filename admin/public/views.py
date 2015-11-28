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

# No login required for document viewer.
# TODO: Handle
#  - bad txn id (CertChain will return blank response)
#  - bad document (exception will be thrown)
def document(request, docid):
  try:
    resp = requests.get(create_rpc_url('/document/' + docid))
    json = resp.json()
    return render(request, 'public/document.html',
      {'docid' : docid, 'doc' : json['contents'], 'raw_data': resp.text})
  except Exception as ex:
    messages.error(request, 'Unable to retrieve document at this time: ' + str(ex))
    return redirect(reverse('certchain:manage_certifications'))

# Allows public users to see raw JSON data via link;
# we cannot link directly to the RPC port as that is
# not intended to be publicly accessible.
def raw_document(request, docid):
  resp = requests.get(create_rpc_url('/document/' + docid))
  return HttpResponse(resp.text, content_type='application/json')

def student(request, student_id):
  try:
    resp = requests.get(create_rpc_url('/certifications_by_student_id/' + student_id))
    certs_by_type = defaultdict(list)
    for c in resp.json():
      if c['cert_timestamp']:
        c['cert_timestamp'] = datetime.datetime.fromtimestamp(int(c['cert_timestamp']))
      if c['rev_timestamp']:
        c['rev_timestamp'] = datetime.datetime.fromtimestamp(int(c['rev_timestamp']))
      certs_by_type[c['doc_type']].append(c)
    return render(request, 'public/student.html',\
      {'certs_by_type' : certs_by_type.iteritems(),
       'student_id': student_id,
      })
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time: ' + str(ex))
    return render(request, 'public/student.html', {'student_id': student_id})