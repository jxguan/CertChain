from .base import *

INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'tokyo'
INSTITUTION_CERTCHAIN_NODE_RPC_PORT = '6001'

TEMPLATE_DIRS = [
  os.path.join(BASE_DIR, 'templates'),
  os.path.join(BASE_DIR, 'templates_tokyo')
]

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db_tokyo.sqlite3'),
    }
}
