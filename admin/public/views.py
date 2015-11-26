import requests, json, base64
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.urlresolvers import reverse
from certchain.shared import create_rpc_url
from collections import defaultdict
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
      {'doc' : json['contents'], 'raw_data': resp.text})
  except Exception as ex:
    messages.error(request, 'Unable to retrieve document at this time: ' + str(ex))
    return redirect(reverse('certchain:manage_certifications'))
  # context = {
  #   'txnid': txnid
  # }
  # try:
  #   document = base64.b64decode(docb64)
  #   context['doc'] = document
  #   payload = {
  #     'txn_id': txnid,
  #     'document': document
  #   }
  #   resp = requests.post(create_rpc_url('/diploma_status'),
  #     data=json.dumps(payload))
  #   latest_txn_id = None
  #   if resp.status_code == 200:
  #     validity = resp.json()
  #     if validity['status'] == 'QUEUED':
  #       context['msg_class'] = 'yellow'
  #       context['msg'] = 'This diploma has just been submitted for \
  #             certification; its validity status\
  #             will be available soon.'
  #     elif validity['status'] == 'CERTIFIED':
  #       context['latest_txn_id'] = validity['latest_txn_id']
  #       context['msg_class'] = 'green'
  #       context['msg'] = 'Certified by ' + cc_addr_to_name(validity['author_addr'])\
  #         + ' on ' + str(cc_format_sig_ts(validity['latest_txn_ts'])) + '. \
  #         This diploma is valid and has not been tampered with.'
  #     elif validity['status'] == 'REVOKED':
  #       context['latest_txn_id'] = validity['latest_txn_id']
  #       context['msg_class'] = 'red'
  #       context['msg'] = 'Revoked by ' + cc_addr_to_name(validity['author_addr'])\
  #         + ' on ' + str(cc_format_sig_ts(validity['latest_txn_ts'])) + '. \
  #         This diploma is no longer valid.'
  #     elif validity['status'] == 'NONEXISTENT':
  #       context['msg_class'] = 'red'
  #       context['msg'] = 'This diploma is not valid; it has never been certified.'
  #     else:
  #       context['msg_class'] = 'red'
  #       context['msg'] = 'This diploma has been tampered with and is not valid.'
  #       context['document_override'] = 'INVALID'
  #   else:
  #     context['msg_class'] = 'red'
  #     context['msg'] = 'A communications error prevented \
  #       the validation of this diploma at the moment: ' + str(resp.status_code)
  # except Exception as ex:
  #   context['msg_class'] = 'red'
  #   context['msg'] = context['msg'] = 'This diploma has been tampered with and is not valid.'
  #   context['document_override'] = 'INVALID'
  # return render(request, 'certchain/viewer.html', context)

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