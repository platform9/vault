import json
import requests


class VaultBase(object):

    def __init__(self, address, token):
        self._addr = address
        self._token = token
        self._session = requests.Session()
        self._session.headers.update({'X-Vault-Token': token})

    def rq(self, verb, path, body=None):
        if body:
            data = json.dumps(body)
        else:
            data = None
        resp = self._session.request(verb,
                                     '%s/v1/%s' %(self._addr, path),
                                     data=data)
        resp.raise_for_status()
        return resp

    @property
    def addr(self):
        return self._addr

    @property
    def token(self):
        return self._token
