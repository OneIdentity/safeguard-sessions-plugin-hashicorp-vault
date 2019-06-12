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
from collections import namedtuple
from enum import Enum
import logging
import requests
import json
import abc

logger = logging.getLogger(__name__)

ApiParams = namedtuple('ApiParams', 'vault_url vault_token secrets_path')


class AuthMethods(Enum):
    APP_ROLE = 'app-role'


class VaultException(Exception):
    pass


class ClientFactory(object):

    def __init__(self, vault_url, vault_token, secrets_path, auth_method, auth_params):
        self._vault_url = vault_url
        self._vault_token = vault_token
        self._secrets_path = secrets_path
        self._auth_method = auth_method
        self._auth_params = auth_params

    def instantiate(self):
        api_params = ApiParams(vault_url=self._vault_url,
                               secrets_path=self._secrets_path,
                               vault_token=self._vault_token)
        if self._auth_method == AuthMethods.APP_ROLE.value:
            role = self._auth_params.get('role')
            if role:
                authenticator = AppRoleAuthenticator(api_params, role)
            else:
                raise VaultException('Missing "role" parameter for auth method {}'.format(self._auth_method))
        else:
            raise VaultException('Auth method not valid: {}'.format(self._auth_method))
        return Client(api_params, authenticator)

    @classmethod
    def from_config(cls, config):
        auth_method = config.getienum('hashicorp_vault', 'auth_method', (AuthMethods.APP_ROLE.value,),
                                      default=AuthMethods.APP_ROLE.value)
        auth_params = dict(role=config.get('hashicorp_vault_approle_authentication', 'role'))
        return ClientFactory(
            vault_url='http://{}:{}'.format(
                config.get('hashicorp_vault', 'address'),
                config.getint('hashicorp_vault', 'port', default=8200),
            ),
            vault_token=config.get('hashicorp_vault', 'token'),
            secrets_path=config.get('hashicorp_vault', 'secrets_path'),
            auth_method=auth_method,
            auth_params=auth_params
        )


class Client(object):

    def __init__(self, api_params, authenticator):
        self._vault_url = api_params.vault_url
        self._vault_token = api_params.vault_token
        self._secrets_path = api_params.secrets_path
        self._authenticator = authenticator
        logger.debug('Http client initialized for URL: {}'.format(self._vault_url))

    def get_secret(self, key):
        client_token = self._authenticator.authenticate()
        secret = _extract_data_from_endpoint(endpoint_url=self._vault_url + '/v1' + self._secrets_path,
                                             data_path='data.' + key,
                                             token=client_token,
                                             method='get')
        return secret


class Authenticator(abc.ABC):

    @abc.abstractmethod
    def authenticate(self):
        pass


class AppRoleAuthenticator(Authenticator):

    def __init__(self, api_params, role):
        self._vault_url = api_params.vault_url
        self._vault_token = api_params.vault_token
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
