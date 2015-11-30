from .base import *

ALLOWED_HOSTS = ['ireland.certchain.org', 'localhost']
INSTITUTION_CERTCHAIN_NODE_HOSTNAME = 'localhost'
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
