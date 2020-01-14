
import json
import logging
import mock
import requests
from vaultlib.ca import VaultCA
from tests import BaseTestCase

LOG = logging.getLogger(__name__)

class TestVaultCA(BaseTestCase):

    def setUp(self):
        super(TestVaultCA, self).setUp()
        self._request = self._patchobj(requests.sessions.Session, 'request')
        self._url = 'http://fake:8200'
        self._ca = VaultCA(self._url, 'fake-token', 'my_ca_pref/myca', 'myca')

    def _check(self, verb, path, body_checks=None):
        call_verb = self._request.call_args[0][0]
        call_url = self._request.call_args[0][1]
        self.assertEqual(verb, call_verb)
        self.assertEqual('%s/v1/%s' % (self._url, path), call_url)

        if body_checks:
            call_data = json.loads(self._request.call_args[1]['data'])
            for body_check in body_checks:
                body_check(call_data)

    def test_create_ca(self):
        self._request.return_value = self.http_response(204, {}, {})
        self._ca.create_ca('This is my ca', maxttl='10h')
        self._check('POST', 'sys/mounts/my_ca_pref/myca', body_checks=[
            lambda b: self.assertEqual('pki', b['type'])
        ])

    def test_delete_ca(self):
        self._request.return_value = self.http_response(200, {}, {})
        self._ca.delete_ca()
        self._check('DELETE', 'sys/mounts/my_ca_pref/myca')

    def test_new_ca_root(self):
        self._request.side_effect = [self.http_response(200, {}, {}),
                                     self.http_response(200, {}, {})]
        self._ca.new_ca_root('myca')
        self._request.assert_has_calls([
            mock.call('DELETE', 'http://fake:8200/v1/my_ca_pref/myca/root', data=None),
            mock.call('POST',
                      'http://fake:8200/v1/my_ca_pref/myca/root/generate/internal',
                      data='{"common_name": "myca", "ttl": "8760h"}')
        ])

    def test_create_signing_role(self):
        self._request.return_value = self.http_response(204, {}, {})
        self._ca.create_signing_role('myrole')
        self._check('POST', 'my_ca_pref/myca/roles/myrole')

    def test_create_signing_token_policy(self):
        self._request.return_value = self.http_response(204, {}, {})
        self._ca.create_signing_token_policy('myrole', 'mypolicy')
        def _check_policy(body):
            policy = body['policy']
            self.assertTrue(policy.startswith('path "my_ca_pref/myca/sign/myrole"'))

        self._check('PUT', 'sys/policy/mypolicy', body_checks=[_check_policy])

    def test_create_token(self):
        self._request.return_value = self.http_response(204, {}, {})
        self._ca.create_token('mypolicy')
        self._check('POST', 'auth/token/create', body_checks=[
            lambda b: self.assertEqual(['mypolicy'], b['policies'])
        ])

    def test_sign_csr(self):
        self._request.return_value = self.http_response(201, {}, {})
        self._ca.sign_csr('myrole', 'csr_pem_string',
                          alt_names=['larry', 'moe', 'curly'])
        self._check('POST', 'my_ca_pref/myca/sign/myrole', body_checks=[
            lambda b: self.assertEqual('csr_pem_string', b['csr']),
            lambda b: self.assertEqual('larry,moe,curly', b['alt_names'])
        ])

    def test_ca_pref_parse(self):
        self.assertEqual('myca', self._ca._common_name)
        self.assertEqual('my_ca_pref/myca', self._ca._ca_func_path)
        self.assertEqual('sys/mounts/my_ca_pref/myca', self._ca._ca_mount_path)

        no_pref_ca = VaultCA(self._url, 'fake-token', 'myca', 'myca')
        self.assertEqual('myca', no_pref_ca._common_name)
        self.assertEqual('myca', no_pref_ca._ca_func_path)
        self.assertEqual('sys/mounts/myca', no_pref_ca._ca_mount_path)
