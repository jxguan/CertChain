from .base import *

INSTITUTION_CERTCHAIN_ADDRESS = 'cgEd7tkQzgqxmegvCY8fy5kB9zFDx4fQVt'
INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'ireland.certchain.org'
INSTITUTION_CERTCHAIN_NODE_RPC_PORT = '4001'

TEMPLATE_DIRS = [
  os.path.join(BASE_DIR, 'templates'),
  os.path.join(BASE_DIR, 'templates_ireland')
]

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db_ireland.sqlite3'),
    }
}