from .base import *

ALLOWED_HOSTS = ['stanford.certchain.org', 'localhost']
INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'localhost'
INSTITUTION_CERTCHAIN_NODE_RPC_PORT = '5001'

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
