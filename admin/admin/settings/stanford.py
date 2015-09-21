from .base import *

INSTITUTION_CERTCHAIN_ADDRESS = 'ch5rFRFu5VCL1cadRLpSdA3K2xJeK4bUyw'
INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'stanford.certchain.org'
INSTITUTION_CERTCHAIN_NODE_RPC_PORT = '4001'

TEMPLATE_DIRS = [
  os.path.join(BASE_DIR, 'templates'),
  os.path.join(BASE_DIR, 'templates_stanford'),
]

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db_stanford.sqlite3'),
    }
}