from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib import messages
import requests, json
from django.core.urlresolvers import reverse
from django.conf import settings
from templatetags.certchain_extras import cc_addr_to_name

# NOTE: relpath should have leading '/'
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
  # For each institution on the network other than ourselves,
  # determine if we trust them or not, and note that so we
  # can determine which button to show. Also note that
  # if we appear in the list, we insert ourself at the front
  # of the list so we appear at the top of the trust list page.
  for inst_addr, trusting_addrs in trust_table.iteritems():
    if inst_addr == settings.INSTITUTION_CERTCHAIN_ADDRESS:
      trust_list.insert(0, (inst_addr, trusting_addrs))
    else:
      trust_list.append((inst_addr, trusting_addrs))
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