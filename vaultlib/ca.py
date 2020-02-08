import logging

from copy import deepcopy
from vaultlib.base import VaultBase
from requests.exceptions import HTTPError

LOG = logging.getLogger(__name__)


class VaultCA(VaultBase):
    def __init__(self, vault_addr, vault_token, vault_pki_path, customer_shortname):
        super(VaultCA, self).__init__(vault_addr, vault_token)

        self._common_name = customer_shortname
        self._ca_func_path = vault_pki_path
        self._ca_mount_path = 'sys/mounts/' + self._ca_func_path

    def create_ca(self, description, maxttl='8760h'):
        """
        Create a new CA in vault. If it already exists, do nothing.
        """
        body = {
            'type': 'pki',
            'description': description,
            'config': {'max_lease_ttl': maxttl}
        }

        LOG.info('Mounting pki vault backend at \'%s\'.', self._ca_mount_path)
        try:
            self.rq('POST', self._ca_mount_path, body)
        except HTTPError as e:
            already_exists = ('existing mount' in e.response.text or
                              'already in use' in e.response.text)
            if already_exists:
                pass
            else:
                raise

    def get_ca(self):
        """
        Get the cert for a named CA.
        """
        LOG.info('Fetching CA cert for \'%s\'', self._ca_func_path)
        return self.rq('GET', '%s/cert/ca' % self._ca_func_path)

    def delete_ca(self):
        """
        Delete a named CA
        """
        LOG.info('Removing CA and invalidating all certs signed by \'%s\'',
                 self._ca_func_path)
        return self.rq('DELETE', self._ca_mount_path)

    def new_ca_root(self, common_name=None, ttl='8760h'):
        """
        Add or replace a root certificate in the named CA.
        """
        self.rq('DELETE', '%s/root' % self._ca_func_path)

        body = {
            'common_name': common_name or self._common_name,
            'ttl': ttl
        }
        LOG.info('Adding or replacing CA certificate for \'%s\' '
                 'with common name \'%s\'.', self._ca_func_path, common_name)
        return self.rq('POST', '%s/root/generate/internal' % self._ca_func_path, body)

    def create_signing_role(self, role_name, options=None):
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
                 self._ca_func_path)
        return self.rq('POST', '%s/roles/%s' % (self._ca_func_path, role_name), body)

    def create_signing_token_policy(self, role_name, policy_name):
        """
        Create an access policy associated with the ability to sign certs
        with the given ca_name and role. This policy can be used to create
        limited-access authentication tokens.
        """
        capabilities = ['create', 'read', 'update', 'delete', 'list']

        policy = 'path \"%s/sign/%s\" {capabilities = [%s]}' % \
                 (self._ca_func_path, role_name, ','.join(['\"%s\"' % c for c in capabilities]))

        body = {"name": policy_name, "policy": policy}

        LOG.info('Creating access policy \'%s\' on CA \'%s\' for role \'%s\' ',
                 policy_name, self._common_name, role_name)
        return self.rq('PUT', 'sys/policy/%s' % policy_name, body)

    def create_token(self, policy_name, token_role=''):
        """
        Create a token for the provided access policy, and role if specified.
        """
        LOG.info('Creating a new vault access token for with policy \'%s\' and role \'%s\'',
                 policy_name, token_role)

        create_path = 'auth/token/create'
        if token_role:
            create_path = create_path + '/' + token_role

        return self.rq('POST', create_path, {'policies': [policy_name]})

    def sign_csr(self, role, csr_pem, common_name=None, ip_sans=None,
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
                 'for common_name = \'%s\'', self._ca_func_path, role,
                 common_name or 'unknown')
        return self.rq('POST', '%s/sign/%s' % (self._ca_func_path, role), body)
