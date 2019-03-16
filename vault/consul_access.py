
import logging
import requests
from base64 import b64encode, b64decode
from vault.base import VaultBase

LOG = logging.getLogger(__name__)


class VaultConsulAccess(VaultBase):

    def create_access_role(self, rolename, policy):
        """
        Returns true if a change was made.
        """
        path = 'consul/roles/%s' % rolename
        LOG.info('Creating a vault role \'%s\' for the consul secrets backend '
                 'with policy \'%s\'.', rolename, policy)
        try:
            resp = self.rq('GET', path)
            existing_policy = \
                b64decode(resp.json().get('data', {}).get('policy', ''))
            if policy == existing_policy:
                return False
            else:
                LOG.info('Updating existing policy, old policy = %s',
                          existing_policy)
        except requests.HTTPError as e:
            if e.response.status_code != 404:
                raise
            else:
                LOG.info('Policy doesn\'t exist. Creating new')
        policy_b64 = b64encode(policy)
        data = {
            'name': rolename,
            'policy': policy_b64,
            'token_type': 'client'
        }
        self.rq('POST', path, data)
        return True

    def get_token(self, rolename):
        LOG.info('Creating a consul token for vault role \'%s\'', rolename)
        path = 'consul/creds/%s' % rolename
        resp = self.rq('GET', path)
        return resp.json()
