from django import template

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