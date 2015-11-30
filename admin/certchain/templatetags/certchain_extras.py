from django import template
import json, datetime
from django.core.urlresolvers import reverse

register = template.Library()

@register.filter
def cc_addr_to_name(addr):
  if addr == 'cgEd7tkQzgqxmegvCY8fy5kB9zFDx4fQVt':
    return 'University of Ireland'
  elif addr == 'ch5rFRFu5VCL1cadRLpSdA3K2xJeK4bUyw':
    return 'Stanford University'
  elif addr == 'cjwiFLy21hpRNP4aeeX5gpz2nkKYSDv1iJ':
    return 'Tokyo University'
  elif addr == 'cnboQGHmUmUm3WLxZYECeoYrdDRhozfMkg':
    return 'University of Virginia'
  else:
    return '(Unrecognized Institution)'

@register.filter
def cc_trust_ratio(trust_ratio):
  percent = "{0:.0f}%".format(trust_ratio * 100)
  if trust_ratio >= 0.75:
    return "TRUSTED (" + percent + ")"
  else:
    return "NOT TRUSTED (" + percent + ")"

@register.filter
def cc_trust_ratio_class(trust_ratio):
  if trust_ratio >= 0.75:
    return "cc-trusted-ratio"
  else:
    return "cc-not-trusted-ratio"

@register.filter
def cc_extract_recipient(document_json):
  try:
    return json.loads(document_json)['recipient']
  except Exception:
    return ''

@register.filter
def cc_extract_degree(document_json):
  try:
    return json.loads(document_json)['degree']
  except Exception:
    return ''

@register.filter
def cc_extract_conferral_date(document_json):
  try:
    return json.loads(document_json)['conferral_date']
  except Exception:
    return ''

@register.filter
def cc_format_sig_ts(seconds):
  try:
    return datetime.datetime.fromtimestamp(
          int(seconds))
  except Exception:
      return ''

@register.filter
def cc_txn_status_class(txn_status):
  return txn_status.lower()

@register.filter
def cc_unix_epoch_to_date(unix_epoch):
  return datetime.datetime.fromtimestamp(int(unix_epoch))

@register.filter
def cc_doc_viewer_url(doc):
  if doc['doc_type'].lower() == 'diploma':
    return reverse('public:diploma', args=(doc['doc_id'],))
  elif doc['doc_type'].lower() == 'transcript':
    return reverse('public:transcript', args=(doc['doc_id'],))
  else:
    return 'Unrecognized document type.'