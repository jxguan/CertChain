from __future__ import division
import requests, json, base64
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.conf import settings
from templatetags.certchain_extras import cc_addr_to_name, cc_format_sig_ts
from models import Transaction

# NOTE: relpath must have leading '/'
def create_rpc_url(relpath):
  return 'http://' + settings.INSTITUTION_CERTCHAIN_NODE_HOSTNAME\
    + ':' + settings.INSTITUTION_CERTCHAIN_NODE_RPC_PORT + relpath

def trust_table_sort(key):
  if key == settings.INSTITUTION_CERTCHAIN_ADDRESS:
    return 0
  else:
    return 1

@login_required
def overview(request):
  try:
    resp = requests.get(create_rpc_url('/trust_table'))
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time.')
    return render(request, 'certchain/overview.html', {})

  trust_table = resp.json()
  trust_list = []
  can_trust_insts = []
  can_revoke_insts = []

  # Determine for each institution their trusted status.
  for inst_addr, trusting_addrs in trust_table.iteritems():
    # First, calculate the trust ratio for the institution.
    trust_ratio = 0
    if len(trusting_addrs) > 0:
      active_trusting_addrs = 0
      for trusting_addr in trusting_addrs:
        if trusting_addr in trust_table and\
            len(trust_table[trusting_addr]) > 0:
          active_trusting_addrs += 1
      try:
        trust_ratio = active_trusting_addrs / (len(trust_table) - 1)
      except ZeroDivisionError:
        trust_ratio = 0
    # Then, if this institution is, prepend our info to the list.
    if inst_addr == settings.INSTITUTION_CERTCHAIN_ADDRESS:
      trust_list.insert(0, (inst_addr, trusting_addrs, trust_ratio))
    # Otherwise, if not us, append info and determine what actions
    # we can take for this institution.
    else:
      trust_list.append((inst_addr, trusting_addrs, trust_ratio))
      if settings.INSTITUTION_CERTCHAIN_ADDRESS in trusting_addrs:
        can_revoke_insts.append(inst_addr)
      else:
        can_trust_insts.append(inst_addr)

  return render(request, 'certchain/overview.html',\
    {'trust_list' : trust_list,\
    'can_trust_insts' : can_trust_insts,\
    'can_revoke_insts' : can_revoke_insts})


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
def diplomas(request):
  try:
    resp = requests.get(create_rpc_url('/my_txns'))
  except Exception as ex:
    messages.error(request, 'Your institution\'s CertChain node \
      is not available at this time.')
    return render(request, 'certchain/diplomas.html', {})

  txn_doc_map = {}
  for txn in Transaction.objects.all():
    txn_doc_map[txn.txn_id] = txn.document

  txns = resp.json()
  for txn in txns:
    txn_id = txn['txn_id']
    # There should always be a record in the database
    # with a txn id returned by the peer node, but
    # being cautious just in case (this way, record will appear,
    # but with blank document fields).
    if txn_id in txn_doc_map:
      txn['document'] = txn_doc_map[txn_id]
      txn['document_base64'] = base64.b64encode(txn['document'])

  # Order txns by most recent to least.
  txns = sorted(txns, key=lambda txn: txn['signature_ts'], reverse=True)

  return render(request, 'certchain/diplomas.html', {
      'txns' : txns,
    })

@login_required
def certify_diploma(request):
  if request.method == 'POST':
    payload = {
      'recipient': request.POST['recipient'],
      'degree': request.POST['degree'],
      'conferral_date': request.POST['conferral_date']
    }
    # Be careful here; remember that changing the way the document
    # is formatted will create different hashes.
    document = json.dumps(payload, sort_keys=True)
    resp = requests.post(create_rpc_url('/certify_document'),
      data=document)
    if resp.status_code == 200:
      txn_id = resp.text
      Transaction.objects.create(
        txn_id=txn_id,
        document=document
      )
      messages.success(request,\
        'The diploma has been submitted to the network as transaction ' + txn_id)
    else:
      messages.error(request,\
        'An error occurred while processing your \
        certification request: ' + str(resp.status_code))
    return redirect(reverse('certchain:diplomas'))
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

# No login required for document viewer.
# TODO: Handle
#  - bad txn id (CertChain will return blank response)
#  - bad document (exception will be thrown)
def viewer(request, txnid, docb64):
  context = {
    'txnid': txnid
  }
  try:
    document = base64.b64decode(docb64)
    context['doc'] = document
    payload = {
      'txn_id': txnid,
      'document': document
    }
    resp = requests.post(create_rpc_url('/diploma_status'),
      data=json.dumps(payload))
    latest_txn_id = None
    if resp.status_code == 200:
      validity = resp.json()
      if validity['status'] == 'QUEUED':
        context['msg_class'] = 'yellow'
        context['msg'] = 'This diploma has just been submitted for \
              certification; its validity status\
              will be available soon.'
      elif validity['status'] == 'CERTIFIED':
        context['latest_txn_id'] = validity['latest_txn_id']
        context['msg_class'] = 'green'
        context['msg'] = 'Certified by ' + cc_addr_to_name(validity['author_addr'])\
          + ' on ' + str(cc_format_sig_ts(validity['latest_txn_ts'])) + '. \
          This diploma is valid and has not been tampered with.'
      elif validity['status'] == 'REVOKED':
        context['latest_txn_id'] = validity['latest_txn_id']
        context['msg_class'] = 'red'
        context['msg'] = 'Revoked by ' + cc_addr_to_name(validity['author_addr'])\
          + ' on ' + str(cc_format_sig_ts(validity['latest_txn_ts'])) + '. \
          This diploma is no longer valid.'
      elif validity['status'] == 'NONEXISTENT':
        context['msg_class'] = 'red'
        context['msg'] = 'This diploma is not valid; it has never been certified.'
      else:
        context['msg_class'] = 'red'
        context['msg'] = 'This diploma has been tampered with and is not valid.'
    else:
      context['msg_class'] = 'red'
      context['msg'] = 'A communications error prevented \
        the validation of this diploma at the moment: ' + str(resp.status_code)
  except Exception as ex:
    context['document'] = ''
    context['msg_class'] = 'red'
    context['msg'] = context['msg'] = 'This diploma has been tampered with and is not valid.'
  return render(request, 'certchain/viewer.html', context)