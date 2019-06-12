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
import json
from pytest import raises
from unittest.mock import patch, call
from collections import namedtuple
from textwrap import dedent

from safeguard.sessions.plugin.plugin_configuration import PluginConfiguration

from ..client import ClientFactory, Client, VaultException, ApiParams, AuthMethods, AppRoleAuthenticator

Response = namedtuple('Response', 'ok text')

ADDRESS = 'vault-address'
PORT = 1337
AUTH_METHOD = AuthMethods.APP_ROLE.value
URL = 'http://{}:{}'.format(ADDRESS, PORT)
ROLE = 'test-role'
SECRET_KEY = 'key'
SECRET = 'secret'
SECRETS_PATH = '/kv/secret'
ROLE_ID = '9eef5cf1-19d3-0cfb-b9bb-8b6248a17ece'
SECRET_ID = '570bb5c9-2083-242d-5ba0-71224c1d4c48'
CLIENT_TOKEN = 's.menL5xntpcw7RY2fMGDVU4Bo'
VAULT_TOKEN = 's.AjtEPrapWWagEqXFtoNPOpaf'
API_PARAMS = ApiParams(vault_url=URL, secrets_path=SECRETS_PATH, vault_token=VAULT_TOKEN)

ROLE_ID_ENDPOINT = URL + '/v1/auth/approle/role/' + ROLE + '/role-id'
SECRET_ID_ENDPOINT = URL + '/v1/auth/approle/role/' + ROLE + '/secret-id'
LOGIN_ENDPOINT = URL + '/v1/auth/approle/login'
SECRETS_ENDPOINT = URL + '/v1' + SECRETS_PATH

POST_RESPONSES = [
    Response(text=json.dumps({
        'request_id': '5dff16d1-6faa-9a3d-c1d7-0cfe4528701b',
        'lease_id': '',
        'renewable': False,
        'lease_duration': 0,
        'data': {
            'secret_id': SECRET_ID,
            'secret_id_accessor': '97100e76-87e6-a0ea-a9eb-68388cc0ec0d'
        },
        'wrap_info': None,
        'warnings': None,
        'auth': None
    }), ok=True),
    Response(text=json.dumps({
        'request_id': 'c0047be1-ce15-e7cd-3abb-bdba02888783',
        'lease_id': '',
        'renewable': False,
        'lease_duration': 0,
        'data': None,
        'wrap_info': None,
        'warnings': None,
        'auth': {
            'client_token': CLIENT_TOKEN,
            'accessor': 'DeI3XGrWkjYBscmrTJI2BthN',
            'policies': [
                'default',
                'dev-policy',
                'my-policy'
            ],
            'token_policies': [
                'default',
                'dev-policy',
                'my-policy'
            ],
            'metadata': {
                'role_name': ROLE
            },
            'lease_duration': 2764800,
            'renewable': True,
            'entity_id': '39a045eb-8556-c30c-05f1-2be0525080b4',
            'token_type': 'service',
            'orphan': True
        }
    }), ok=True),
]

GET_RESPONSES = [
    Response(text=json.dumps({
        'request_id': '39dcab3e-6890-fbf4-460b-d3f1f49df2b3',
        'lease_id': '',
        'renewable': False,
        'lease_duration': 0,
        'data': {
            'role_id': ROLE_ID
        },
        'wrap_info': None,
        'warnings': None,
        'auth': None
    }), ok=True),
    Response(text=json.dumps({
        'request_id': '969945d0-e8b2-f154-8ca9-9ebca3c25b1e',
        'lease_id': '',
        'renewable': False,
        'lease_duration': 2764800,
        'data': {
            SECRET_KEY: SECRET
        },
        'wrap_info': None,
        'warnings': None,
        'auth': None
    }), ok=True)
]

ERROR_RESPONSE = Response(text=json.dumps({
    'errors': ['This is a generic error']
}), ok=False)


def test_client_factory_raises_exception_if_auth_method_not_valid():
    with raises(VaultException):
        ClientFactory(URL, VAULT_TOKEN, SECRETS_ENDPOINT, 'not-valid', None).instantiate()


def test_client_factory_instantiates_app_role_client():
    client_factory = ClientFactory(URL, VAULT_TOKEN, SECRETS_ENDPOINT, AUTH_METHOD, dict(role=ROLE))
    assert isinstance(client_factory.instantiate(), Client)


def test_client_factory_can_be_instantiated_with_config(mocker):
    config = PluginConfiguration(dedent('''
        [hashicorp_vault]
        address = {}
        port = {}
        token = {}
        secrets_path = {}
        auth_method = {}

        [hashicorp_vault_approle_authentication]
        role = {}
    '''.format(ADDRESS, PORT, VAULT_TOKEN, SECRETS_PATH, AUTH_METHOD, ROLE)))
    mocker.spy(ClientFactory, '__init__')
    client_factory = ClientFactory.from_config(config)
    client_factory.__init__.assert_called_with(
        client_factory,
        vault_url=URL,
        vault_token=VAULT_TOKEN,
        secrets_path=SECRETS_PATH,
        auth_method=AUTH_METHOD,
        auth_params={'role': ROLE}
    )


@patch('requests.post', side_effect=POST_RESPONSES)
@patch('requests.get', side_effect=GET_RESPONSES)
def test_get_secret_by_key(get_mock, post_mock):
    expected_headers = {'X-Vault-Token': VAULT_TOKEN}
    expected_calls_to_get = [
        call(ROLE_ID_ENDPOINT, headers=expected_headers),
        call(SECRETS_ENDPOINT, headers={'X-Vault-Token': CLIENT_TOKEN})
    ]
    expected_calls_to_post = [
        call(SECRET_ID_ENDPOINT, headers=expected_headers, data=None),
        call(LOGIN_ENDPOINT, headers=expected_headers,
             data={'role_id': ROLE_ID, 'secret_id': SECRET_ID})
    ]

    client = Client(API_PARAMS, AppRoleAuthenticator(API_PARAMS, ROLE))
    secret = client.get_secret(key=SECRET_KEY)

    assert secret == SECRET
    get_mock.assert_has_calls(calls=expected_calls_to_get, any_order=False)
    post_mock.assert_has_calls(calls=expected_calls_to_post, any_order=False)


@patch('requests.post', side_effect=POST_RESPONSES)
@patch('requests.get', side_effect=[GET_RESPONSES[0], ERROR_RESPONSE])
def test_error_occurs_when_getting_secret(_get_mock, _post_mock):
    client = Client(API_PARAMS, AppRoleAuthenticator(API_PARAMS, ROLE))
    with raises(VaultException):
        client.get_secret(key=SECRET_KEY)
