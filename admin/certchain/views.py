from __future__ import division
import requests, json, base64
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.conf import settings
from templatetags.certchain_extras import cc_addr_to_name, cc_format_sig_ts
from certchain.shared import create_rpc_url
import os, hashlib

def trust_table_sort(key):
  if key == settings.INSTITUTION_CERTCHAIN_ADDRESS:
    return 0
  else:
    return 1

@login_required
def overview(request):
  try:
    resp = requests.get(create_rpc_url('/network'))
    return render(request, 'certchain/overview.html',\
      {'network' : resp.json()})
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time.')
    return render(request, 'certchain/overview.html', {})

@login_required
def approve_peer_request(request):
  if request.method == 'POST':
    addr = request.POST['requesting_addr']
    resp = requests.post(create_rpc_url('/approve_peerreq/' + addr))
    if resp.status_code == 200:
      messages.success(request,\
        'Your approval was submitted; it may take a few \
        seconds for the approval to be reflected below.')
    else:
      messages.error(request,\
        'An error occurred while processing your \
        peer request approval for ' + addr + '.')
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def request_peer(request):
  if request.method == 'POST':
    addr = request.POST['addr']
    resp = requests.post(create_rpc_url('/request_peer/' + addr))
    if resp.status_code == 200:
      messages.success(request,\
        'Your peering request was successfully submitted.')
    else:
      messages.error(request,\
        'An error occurred while processing your \
        peer request for ' + addr + '.')
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def end_peering(request):
  if request.method == 'POST':
    addr = request.POST['addr']
    resp = requests.post(create_rpc_url('/end_peering/' + addr))
    if resp.status_code == 200:
      messages.success(request,\
        'Your peering termination request was successfully submitted.')
    else:
      messages.error(request,\
        'An error occurred while processing your \
        peering termination request for ' + addr + '.')
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def trust_institution(request):
  if request.method == 'POST':
    addr = request.POST['addr_to_trust']
    payload = {'address' : addr}
    resp = requests.post(create_rpc_url('/trust_institution'),
      data=json.dumps(payload))
    if resp.status_code == 200:
      messages.success(request,\
        'Your trust request for ' + addr + ' was submitted \
        successfully; it will take effect once it is included \
        in a block.')
    else:
      messages.error(request,\
        'An error occurred while processing your trust request \
        for ' + addr + ': ' + str(resp.status_code))
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def untrust_institution(request):
  if request.method == 'POST':
    addr = request.POST['addr_to_untrust']
    payload = {'address' : addr}
    resp = requests.post(create_rpc_url('/untrust_institution'),
      data=json.dumps(payload))
    if resp.status_code == 200:
      messages.success(request,\
        'Your trust revocation request for ' + cc_addr_to_name(addr) + ' was submitted \
        successfully; it will take effect once it is included \
        in a block.')
    else:
      messages.error(request,\
        'An error occurred while processing your trust revocation request \
        for ' + cc_addr_to_name(addr) + ': ' + str(resp.status_code))
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def certify(request):
  return render(request, 'certchain/certify.html', {})

@login_required
def manage_certifications(request):
  try:
    resp = requests.get(create_rpc_url('/all_certifications'))
    return render(request, 'certchain/certifications.html',\
      {'certifications' : resp.json()})
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time: ' + str(ex))
    return render(request, 'certchain/certifications.html', {})

@login_required
def certify_diploma(request):
  if request.method == 'POST':
    student_id = request.POST['student_id']
    payload = {
      'commitment': hashlib.sha256(os.urandom(8)).hexdigest(),
      'student_id': student_id,
      'recipient': request.POST['recipient'],
      'degree': request.POST['degree'],
      'conferral_date': request.POST['conferral_date']
    }
    # Be careful here; remember that changing the way the document
    # is formatted will create different hashes. We also eliminate
    # space b/w separators so that when we recreate the document
    # client-side, we get the same string representation for hashing.
    document = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    resp = requests.post(create_rpc_url('/certify/Diploma/'+student_id),
      data=document)
    if resp.status_code == 200:
      txn_id = resp.text
      messages.success(request,\
        'The diploma has been submitted to the network as transaction ' + txn_id)
    else:
      messages.error(request,\
        'An error occurred while processing your \
        certification request: ' + str(resp.status_code))
    return redirect(reverse('certchain:certify'))
  raise Http404

@login_required
def certify_transcript(request):
  if request.method == 'POST':
    student_id = request.POST['student_id']
    payload = {
      'commitment': hashlib.sha256(os.urandom(8)).hexdigest(),
      'student_id': student_id,
      'recipient': request.POST['recipient'],
      'gpa': request.POST['gpa'],
      'date': request.POST['date']
    }
    # Be careful here; remember that changing the way the document
    # is formatted will create different hashes. We also eliminate
    # space b/w separators so that when we recreate the document
    # client-side, we get the same string representation for hashing.
    document = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    resp = requests.post(create_rpc_url('/certify/Transcript/'+student_id),
      data=document)
    if resp.status_code == 200:
      txn_id = resp.text
      messages.success(request,\
        'The transcript has been submitted to the network as transaction ' + txn_id)
    else:
      messages.error(request,\
        'An error occurred while processing your \
        certification request: ' + str(resp.status_code))
    return redirect(reverse('certchain:certify'))
  raise Http404


@login_required
def revoke_diploma(request):
  if request.method == 'POST':
    txn_id_to_revoke = request.POST['txn_id_to_revoke']
    payload = {
      'txn_id': txn_id_to_revoke
    }
    resp = requests.post(create_rpc_url('/revoke_document'),
      data=json.dumps(payload))
    if resp.status_code == 200:
      txn_id = resp.text
      messages.success(request,\
        'The revocation has been submitted to the network as transaction ' + txn_id)
    else:
      messages.error(request,\
        'An error occurred while processing your \
        revocation request: ' + str(resp.status_code))
    return redirect(reverse('certchain:diplomas'))
  raise Http404