
import logging

from copy import deepcopy
from vault.base import VaultBase
from requests.exceptions import HTTPError

LOG = logging.getLogger(__name__)

class VaultCA(VaultBase):

    def create_ca(self, ca_name, description, maxttl='8760h'):
        """
        Create a new CA in vault. If it already exists, do nothing.
        """
        body = {
            'type': 'pki',
            'description': description,
            'config': {'max_lease_ttl': maxttl}
         }

        LOG.info('Mounting pki vault backend at \'%s\'.', ca_name)
        try:
            self.rq('POST', 'sys/mounts/%s' % ca_name, body)
        except HTTPError as e:
            already_exists = 'existing mount' in e.response.text
            if already_exists:
                pass
            else:
                raise

    def get_ca(self, ca_name):
        """
        Get the cert for a named CA.
        """
        LOG.info('Fetching CA cert for \'%s\'', ca_name)
        return self.rq('GET', '%s/cert/ca' % ca_name)

    def delete_ca(self, ca_name):
        """
        Delete a named CA
        """
        LOG.info('Removing CA and invalidating all certs signed by \'%s\'',
                 ca_name)
        return self.rq('DELETE', 'sys/mounts/%s' % ca_name)

    def new_ca_root(self, ca_name, common_name=None, ttl='8760h'):
        """
        Add or replace a root certificate in the named CA.
        """
        self.rq('DELETE','%s/root' % ca_name)
        body = {
            'common_name': common_name or ca_name,
            'ttl': ttl
        }
        LOG.info('Adding or replacing CA certificate for \'%s\' '
                 'with common name \'%s\'.', ca_name, common_name)
        return self.rq('POST', '%s/root/generate/internal' % ca_name, body)

    def create_signing_role(self, ca_name, role_name, options=None):
        """
        Create a signing role containing a set of default options for certs
        signed by this CA. See https://www.vaultproject.io/api/secret/pki/index.html#create-update-role
        for a list of options.
        """
        if options:
            body = deepcopy(options)
        else:
            body = {}
        body.update({
            'key_bits': 2048,
            'allow_any_name': True,
            'use_csr_sans': False,
            'use_csr_common_name': False
        })
        LOG.info('Creating a new signing role \'%s\' for \'%s\'',
                 role_name,
                 ca_name)
        return self.rq('POST', '%s/roles/%s' % (ca_name, role_name), body)

    def create_signing_token_policy(self, ca_name, role_name, policy_name):
        """
        Create an access policy associated with the ability to sign certs
        with the given ca_name and role. This policy can be used to create
        limited-access authentication tokens.
        """
        capabilities=['create', 'read', 'update', 'delete', 'list']
        policy = 'path \"%s/sign/%s\" {capabilities = [%s]}' % \
            (ca_name, role_name, ','.join(['\"%s\"' % c for c in capabilities]))
        body = {"name": policy_name, "policy": policy}
        LOG.info('Creating access policy \'%s\' on CA \'%s\' for role \'%s\' ',
                 policy_name, ca_name, role_name)
        return self.rq('PUT', 'sys/policy/%s' % policy_name, body)

    def create_token(self, policy_name):
        """
        Create a token for the provided access policy.
        """
        LOG.info('Creating a new vault access token for with policy \'%s\'',
                 policy_name)
        return self.rq('POST', 'auth/token/create',
                        {'policies': [policy_name]})

    def sign_csr(self, ca_name, role, csr_pem, common_name=None, ip_sans=None,
                 alt_names=None, ttl='730h'):
        """
        Sign a PEM-encoded CSR.
        """
        body = {
            'csr': csr_pem,
            'ttl': ttl
        }
        if common_name:
            body['common_name'] = common_name
        if alt_names:
            body['alt_names'] = ','.join(alt_names)
        if ip_sans:
            body['ip_sans'] = ','.join(ip_sans)

        LOG.info('Requesting a new certificate from \'%s\' for role \'%s\' '
                 'for common_name = \'%s\'', ca_name, role,
                 common_name or 'unknown')
        return self.rq('POST', '%s/sign/%s' % (ca_name, role), body)
