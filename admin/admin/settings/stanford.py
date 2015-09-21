from .base import *

INSTITUTION_CERTCHAIN_ADDRESS = 'ch5rFRFu5VCL1cadRLpSdA3K2xJeK4bUyw'
INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'stanford.certchain.org'
INSTITUTION_CERTCHAIN_NODE_RPC_PORT = '4001'

TEMPLATE_DIRS = [
  os.path.join(BASE_DIR, 'templates'),
  os.path.join(BASE_DIR, 'templates_stanford'),
]