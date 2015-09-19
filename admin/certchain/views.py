from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.contrib import messages
import requests, json
from django.core.urlresolvers import reverse

@login_required
def overview(request):
  resp = requests.get('http://localhost:5001/trust_table')
  trust_table = resp.json()
  return render(request, 'certchain/overview.html',\
    {'trust_table' : trust_table})

@login_required
def trust_institution(request):
  if request.method == 'POST':
    addr = request.POST['addr_to_trust']
    payload = {'address' : addr}
    resp = requests.post('http://localhost:5001/trust_institution',
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