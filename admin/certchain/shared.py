from django.conf import settings

# NOTE: relpath must have leading '/'
def create_rpc_url(relpath):
  return 'http://' + settings.INSTITUTION_CERTCHAIN_NODE_HOSTNAME\
    + ':' + settings.INSTITUTION_CERTCHAIN_NODE_RPC_PORT + relpath