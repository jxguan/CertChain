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
def add_node(request):
  if request.method == 'POST':
    payload = {
      'hostname': request.POST['hostname'],
      'port': request.POST['port'],
      'address': request.POST['address']
    }
    resp = requests.post(create_rpc_url('/add_node'),
      data=json.dumps(payload))
    if resp.status_code == 200 and resp.text == 'OK':
      messages.success(request,\
        'The node was added to the list of known nodes.')
    else:
      messages.error(request,\
        'An error occurred while adding the node you specified: '
        + str(resp.text))
    return redirect(reverse('certchain:overview'))
  raise Http404

@login_required
def remove_node(request):
  if request.method == 'POST':
    inst_addr = request.POST['inst_addr']
    resp = requests.post(create_rpc_url('/remove_node/' + inst_addr))
    if resp.status_code == 200 and resp.text == 'OK':
      messages.success(request,\
        'The node was removed from the list of known nodes.')
    else:
      messages.error(request,\
        'An error occurred while removing the node you specified: '
        + str(resp.text))
    return redirect(reverse('certchain:overview'))
  raise Http404

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
    if resp.status_code == 200 and resp.text == 'OK':
      messages.success(request,\
        'The diploma has been submitted to the network for certification.')
    else:
      messages.error(request,\
        'An error occurred while processing your \
        certification request: ' + resp.text)
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
    if resp.status_code == 200 and resp.text == 'OK':
      messages.success(request,\
        'The transcript has been submitted to the network for certification.')
    else:
      messages.error(request,\
        'An error occurred while processing your \
        certification request: ' + resp.text)
    return redirect(reverse('certchain:certify'))
  raise Http404

@login_required
def revoke_document(request):
  if request.method == 'POST':
    docid = request.POST['docid_to_revoke']
    resp = requests.post(create_rpc_url('/revoke/' + docid))
    if resp.status_code == 200:
      messages.success(request,\
        'Your document revocation request has been submitted to the network.')
    else:
      messages.error(request,\
        'An error occurred while processing your revocation \
        request: ' + str(resp.status_code))
    return redirect(reverse('certchain:manage_certifications'))
  raise Http404
