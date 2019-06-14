#
#   Copyright (c) 2019 One Identity
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from functools import reduce
import logging
import requests
import json
import abc

logger = logging.getLogger(__name__)


class VaultException(Exception):
    pass


class ClientFactory(object):

    def __init__(self, authenticator, secret_retriever):
        self._authenticator = authenticator
        self._secret_retriever = secret_retriever

    @property
    def authenticator(self):
        return self._authenticator

    @property
    def secret_retriever(self):
        return self._secret_retriever

    def instantiate(self):
        return Client(self._authenticator, self._secret_retriever)

    @classmethod
    def from_config(cls, config):
        vault_url = 'http://{}:{}'.format(config.get('hashicorp_vault', 'address', required=True),
                                          config.getint('hashicorp_vault', 'port', default=8200))
        role = config.get('hashicorp_vault_approle_authentication', 'role')
        if role:
            vault_token = config.get('hashicorp_vault_approle_authentication', 'vault_token')
            authenticator = AppRoleAuthenticator(vault_url, role, vault_token)
        else:
            raise VaultException('No valid auth method can be determined based on config')

        secrets_path = config.get('hashicorp_vault_secrets_engine_kv_v1', 'secrets_path')
        if secrets_path:
            secret_retriever = KVEngineV1SecretRetriever(vault_url, secrets_path)
        else:
            raise VaultException('No valid secrets engine can be determined based on config')

        return ClientFactory(authenticator, secret_retriever)


class Client(object):

    def __init__(self, authenticator, secret_retriever):
        self._authenticator = authenticator
        self._secret_retriever = secret_retriever

    def get_secret(self, key):
        client_token = self._authenticator.authenticate()
        secret = self._secret_retriever.retrieve_secret(key, client_token)
        return secret


class SecretRetriever(abc.ABC):

    @abc.abstractmethod
    def retrieve_secret(self, key, client_token):
        pass


class KVEngineV1SecretRetriever(SecretRetriever):

    def __init__(self, vault_url, secrets_path):
        self._vault_url = vault_url
        self._secrets_path = secrets_path

    def retrieve_secret(self, key, client_token):
        secret = _extract_data_from_endpoint(endpoint_url=self._vault_url + '/v1/' + self._secrets_path,
                                             data_path='data.' + key,
                                             token=client_token,
                                             method='get')
        return secret


class Authenticator(abc.ABC):

    @abc.abstractmethod
    def authenticate(self):
        pass


class AppRoleAuthenticator(Authenticator):

    def __init__(self, vault_url, vault_token, role):
        self._vault_url = vault_url
        self._vault_token = vault_token
        self._role = role

    def authenticate(self):
        role_id = _extract_data_from_endpoint(endpoint_url=self._vault_url + '/v1/auth/approle/role/' + self._role + '/role-id',
                                              data_path='data.role_id',
                                              token=self._vault_token,
                                              method='get')
        secret_id = _extract_data_from_endpoint(endpoint_url=self._vault_url + '/v1/auth/approle/role/' + self._role + '/secret-id',
                                                data_path='data.secret_id',
                                                token=self._vault_token,
                                                method='post')
        client_token = _extract_data_from_endpoint(endpoint_url=self._vault_url + '/v1/auth/approle/login',
                                                   data_path='auth.client_token',
                                                   token=self._vault_token,
                                                   method='post',
                                                   data={'role_id': role_id, 'secret_id': secret_id})
        return client_token


def _extract_data_from_endpoint(endpoint_url, data_path, token, method, data=None):
    headers = {'X-Vault-Token': token}
    logger.debug('Sending http request to Hashicorp Vault, endpoint_url="{}", method="{}"'
                 .format(endpoint_url, method))
    try:
        response = requests.get(endpoint_url, headers=headers) if method == 'get' \
            else requests.post(endpoint_url, headers=headers, data=json.dumps(data) if data else None)
    except requests.exceptions.ConnectionError as exc:
        raise VaultException('Connection error: {}'.format(exc))
    if response.ok:
        logger.debug('Got correct response from endpoint: {}'.format(endpoint_url))
        return reduce(dict.get, data_path.split('.'), json.loads(response.text))
    else:
        raise VaultException('Received error from Hashicorp Vault: {}'
                             .format(json.loads(response.text).get('errors')[0]))
