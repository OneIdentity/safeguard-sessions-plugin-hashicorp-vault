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
import pytest
import json
from requests.exceptions import ConnectionError
from pytest import raises
from unittest.mock import patch, call, MagicMock
from collections import namedtuple
from textwrap import dedent
from contextlib import contextmanager

from safeguard.sessions.plugin.logging import configure as log_configure
from safeguard.sessions.plugin.plugin_configuration import PluginConfiguration
from safeguard.sessions.plugin.endpoint_extractor import EndpointException

from ..client import (
    Client,
    InvalidConfigurationError,
    VaultException,
    AppRoleAuthenticator,
    PasswordTypeAuthenticator,
    KVEngineV1SecretRetriever,
)

Response = namedtuple("Response", "ok text status_code")

ADDRESS = "vault-address"
PORT = 1337
URL = "http://{}:{}".format(ADDRESS, PORT)
ROLE = "test-role"
SECRET_KEY = "key"
SECRET = "secret"
SECRETS_PATH = "kv/secret"
ROLE_ID = "9eef5cf1-19d3-0cfb-b9bb-8b6248a17ece"
SECRET_ID = "570bb5c9-2083-242d-5ba0-71224c1d4c48"
CLIENT_TOKEN = "s.menL5xntpcw7RY2fMGDVU4Bo"
VAULT_TOKEN = "s.AjtEPrapWWagEqXFtoNPOpaf"
AUTHENTICATOR = AppRoleAuthenticator(URL, VAULT_TOKEN, ROLE)
SECRET_RETRIEVER = KVEngineV1SecretRetriever(URL, SECRETS_PATH)

ROLE_ID_ENDPOINT = URL + "/v1/auth/approle/role/" + ROLE + "/role-id"
SECRET_ID_ENDPOINT = URL + "/v1/auth/approle/role/" + ROLE + "/secret-id"
LOGIN_ENDPOINT = URL + "/v1/auth/approle/login"
SECRETS_ENDPOINT = URL + "/v1/" + SECRETS_PATH


HASHICORP_VAULT_APPROLE_AUTH_CONFIG = dedent(
    """
    [approle-authentication]
    role = {}
    vault_token = {}
""".format(
        ROLE, VAULT_TOKEN
    )
)

HASHICORP_VAULT_KV_V1_CONFIG = dedent(
    """
    [engine-kv-v1]
    secrets_path = {}
""".format(
        SECRETS_PATH
    )
)


POST_RESPONSES = [
    Response(
        text=json.dumps(
            {
                "request_id": "5dff16d1-6faa-9a3d-c1d7-0cfe4528701b",
                "lease_id": "",
                "renewable": False,
                "lease_duration": 0,
                "data": {"secret_id": SECRET_ID, "secret_id_accessor": "97100e76-87e6-a0ea-a9eb-68388cc0ec0d"},
                "wrap_info": None,
                "warnings": None,
                "auth": None,
            }
        ),
        ok=True,
        status_code=200,
    ),
    Response(
        text=json.dumps(
            {
                "request_id": "c0047be1-ce15-e7cd-3abb-bdba02888783",
                "lease_id": "",
                "renewable": False,
                "lease_duration": 0,
                "data": None,
                "wrap_info": None,
                "warnings": None,
                "auth": {
                    "client_token": CLIENT_TOKEN,
                    "accessor": "DeI3XGrWkjYBscmrTJI2BthN",
                    "policies": ["default", "dev-policy", "my-policy"],
                    "token_policies": ["default", "dev-policy", "my-policy"],
                    "metadata": {"role_name": ROLE},
                    "lease_duration": 2764800,
                    "renewable": True,
                    "entity_id": "39a045eb-8556-c30c-05f1-2be0525080b4",
                    "token_type": "service",
                    "orphan": True,
                },
            }
        ),
        ok=True,
        status_code=200,
    ),
]

GET_RESPONSES = [
    Response(
        text=json.dumps(
            {
                "initialized": True,
                "sealed": False,
                "standby": False,
                "performance_standby": False,
                "replication_performance_mode": "disabled",
                "replication_dr_mode": "disabled",
                "server_time_utc": 1568365137,
                "version": "1.1.2",
                "cluster_name": "vault-cluster-eba4a26a",
                "cluster_id": "df107efd-43e2-b4a0-a0ac-939e3cead978",
            }
        ),
        ok=True,
        status_code=200,
    ),
    Response(
        text=json.dumps(
            {
                "request_id": "39dcab3e-6890-fbf4-460b-d3f1f49df2b3",
                "lease_id": "",
                "renewable": False,
                "lease_duration": 0,
                "data": {"role_id": ROLE_ID},
                "wrap_info": None,
                "warnings": None,
                "auth": None,
            }
        ),
        ok=True,
        status_code=200,
    ),
    Response(
        text=json.dumps(
            {
                "request_id": "969945d0-e8b2-f154-8ca9-9ebca3c25b1e",
                "lease_id": "",
                "renewable": False,
                "lease_duration": 2764800,
                "data": {SECRET_KEY: SECRET},
                "wrap_info": None,
                "warnings": None,
                "auth": None,
            }
        ),
        ok=True,
        status_code=200,
    ),
]

ERROR_RESPONSE_NOT_FOUND = Response(text=json.dumps({"errors": ["This is a generic error"]}), ok=False, status_code=404)


ERROR_RESPONSE_NO_SUCH_FIELD = Response(
    text=json.dumps(
        {
            "request_id": "969945d0-e8b2-f154-8ca9-9ebca3c25b1e",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 2764800,
            "data": {},
            "wrap_info": None,
            "warnings": None,
            "auth": None,
        }
    ),
    ok=True,
    status_code=200,
)


PERFORMANCE_STANDBY_HEALTH_RESPONSE = Response(
    text=json.dumps(
        {
            "initialized": True,
            "sealed": False,
            "standby": False,
            "performance_standby": True,
            "replication_performance_mode": "disabled",
            "replication_dr_mode": "disabled",
            "server_time_utc": 1568365137,
            "version": "1.1.2",
            "cluster_name": "vault-cluster-eba4a26a",
            "cluster_id": "df107efd-43e2-b4a0-a0ac-939e3cead978",
        }
    ),
    ok=True,
    status_code=473,
)

VAULT_DOWN = Response(
    text=json.dumps(
        {
            "initialized": True,
            "sealed": False,
            "standby": False,
            "performance_standby": False,
            "replication_performance_mode": "disabled",
            "replication_dr_mode": "disabled",
            "server_time_utc": 1568365137,
            "version": "1.1.2",
            "cluster_name": "vault-cluster-eba4a26a",
            "cluster_id": "df107efd-43e2-b4a0-a0ac-939e3cead978",
        }
    ),
    ok=False,
    status_code=401,
)


@contextmanager
def _open_session():
    yield SESSION


SESSION = MagicMock()
REQUESTS_TLS = MagicMock()
REQUESTS_TLS.tls_enabled = False
REQUESTS_TLS.open_session = _open_session


def hashicorp_vault_config(address=ADDRESS, auth_method="approle", extra_parts=""):
    return dedent(
        """
        [logging]
        log_level=debug

        [hashicorp]
        address = {}
        port = {}
        authentication_method = {}
        {}
        """.format(
            address, PORT, auth_method, extra_parts
        )
    )


def test_client_can_be_instantiated():
    client = Client(REQUESTS_TLS, AUTHENTICATOR, SECRET_RETRIEVER)
    assert isinstance(client, Client)


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_client_can_be_instantiated_with_config(_requests_tls, mocker):
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.side_effect = GET_RESPONSES
    config = create_config_and_set_loglevel(
        hashicorp_vault_config() + HASHICORP_VAULT_APPROLE_AUTH_CONFIG + HASHICORP_VAULT_KV_V1_CONFIG
    )
    mocker.spy(Client, "__init__")
    mocker.spy(AppRoleAuthenticator, "__init__")
    mocker.spy(KVEngineV1SecretRetriever, "__init__")
    client = Client.create_client(config, "username", "pw")
    client.__init__.assert_called_with(client, client.session_factory, client.authenticator, client.secret_retriever)
    client.authenticator.__init__.assert_called_with(client.authenticator, URL, VAULT_TOKEN, ROLE)
    client.secret_retriever.__init__.assert_called_with(client.secret_retriever, URL, SECRETS_PATH)


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_client_factory_uses_HTTPS_when_TLS_enabled(_requests_tls, mocker):
    SESSION.get.side_effect = GET_RESPONSES
    REQUESTS_TLS.tls_enabled = True
    https_url = "https://{}:{}".format(ADDRESS, PORT)
    config = create_config_and_set_loglevel(
        hashicorp_vault_config() + HASHICORP_VAULT_APPROLE_AUTH_CONFIG + HASHICORP_VAULT_KV_V1_CONFIG
    )
    mocker.spy(AppRoleAuthenticator, "__init__")
    mocker.spy(KVEngineV1SecretRetriever, "__init__")
    client = Client.create_client(config, "myuser", "mypassword")
    client.authenticator.__init__.assert_called_with(client.authenticator, https_url, VAULT_TOKEN, ROLE)
    client.secret_retriever.__init__.assert_called_with(client.secret_retriever, https_url, SECRETS_PATH)


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_client_factory_raises_exception_if_secrets_engine_cannot_be_determined(_requests_tls):
    SESSION.get.side_effect = GET_RESPONSES
    config = create_config_and_set_loglevel(hashicorp_vault_config() + HASHICORP_VAULT_APPROLE_AUTH_CONFIG)
    with raises(InvalidConfigurationError):
        Client.create_client(config, "myuser", "mypassword")


def test_get_secret_by_key():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.side_effect = GET_RESPONSES[1:]
    expected_headers = {"X-Vault-Token": VAULT_TOKEN}
    expected_calls_to_get = [
        call(ROLE_ID_ENDPOINT, headers=expected_headers, params=None),
        call(SECRETS_ENDPOINT, headers={"X-Vault-Token": CLIENT_TOKEN}, params=None),
    ]
    expected_calls_to_post = [
        call(SECRET_ID_ENDPOINT, headers=expected_headers, data=None, params=None),
        call(LOGIN_ENDPOINT, headers=expected_headers, data=json.dumps({"role_id": ROLE_ID, "secret_id": SECRET_ID}), params=None),
    ]

    client = Client(REQUESTS_TLS, AUTHENTICATOR, SECRET_RETRIEVER)
    secret = client.get_secret(key=SECRET_KEY)

    assert secret == SECRET
    SESSION.get.assert_has_calls(calls=expected_calls_to_get, any_order=False)
    SESSION.post.assert_has_calls(calls=expected_calls_to_post, any_order=False)


def test_error_occurs_when_getting_secret():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.side_effect = [GET_RESPONSES[1], ERROR_RESPONSE_NOT_FOUND]
    client = Client(REQUESTS_TLS, AUTHENTICATOR, SECRET_RETRIEVER)
    with raises(EndpointException) as exc:
        client.get_secret(key=SECRET_KEY)
    assert exc.match("Endpoint responded with NOK;")


def test_error_occurs_when_extracting_secret():
    SESSION.post.side_effect = POST_RESPONSES
    SESSION.get.side_effect = [GET_RESPONSES[1], ERROR_RESPONSE_NO_SUCH_FIELD]
    client = Client(REQUESTS_TLS, AUTHENTICATOR, SECRET_RETRIEVER)
    with raises(EndpointException) as exc:
        client.get_secret(key=SECRET_KEY)
    assert exc.match("Endpoint \\(http://vault-address:1337/v1/kv/secret\\) response did not contain the information;")


def test_cannot_connect_to_vault():
    SESSION.get.side_effect = [VAULT_DOWN]
    with raises(VaultException):
        Client._determine_vault_to_use(REQUESTS_TLS, ["wrong.address"], "1234")


def data_provider():
    yield ("ldap", PasswordTypeAuthenticator, "use_credential=explicit\nusername=user\npassword=pass")
    yield ("userpass", PasswordTypeAuthenticator, "use_credential=explicit\nusername=user\npassword=pass")
    yield ("approle", AppRoleAuthenticator, "")


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
@pytest.mark.parametrize("auth_method, instance, extra_parts", data_provider())
def test_client_uses_the_appropriate_authenticator(_requests_tls, auth_method, instance, extra_parts):
    SESSION.get.side_effect = GET_RESPONSES
    config = create_config_and_set_loglevel(
        hashicorp_vault_config(auth_method=auth_method, extra_parts=extra_parts)
        + HASHICORP_VAULT_APPROLE_AUTH_CONFIG
        + HASHICORP_VAULT_KV_V1_CONFIG
    )
    client = Client.create_client(config, "myuser", "mypassword")
    assert isinstance(client.authenticator, instance)
    assert client.authenticator.authentication_backend == auth_method


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_raises_vault_error_when_cannot_make_connection_to_vault(_requests_tls):
    SESSION.get.side_effect = [ConnectionError()]
    config = create_config_and_set_loglevel(
        hashicorp_vault_config(
            address="vault.is.down",
            auth_method="ldap",
            extra_parts="use_credential=explicit\nusername=user\npassword=pass",
        )
        + HASHICORP_VAULT_APPROLE_AUTH_CONFIG
        + HASHICORP_VAULT_KV_V1_CONFIG
    )
    with raises(VaultException):
        Client.create_client(config, "myuser", "mypassword")


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_uses_first_available_vault_address_when_more_configured(_requests_tls, mocker):
    SESSION.get.side_effect = [VAULT_DOWN, GET_RESPONSES[0]]
    config = create_config_and_set_loglevel(
        hashicorp_vault_config(
            address="vault.is.down,test.vault", auth_method="ldap", extra_parts="use_credential=gateway"
        )
        + HASHICORP_VAULT_APPROLE_AUTH_CONFIG
        + HASHICORP_VAULT_KV_V1_CONFIG
    )
    mocker.spy(PasswordTypeAuthenticator, "__init__")
    client = Client.create_client(config, "myuser", "mypassword")
    client.authenticator.__init__.assert_called_with(
        client.authenticator, "https://test.vault:{}".format(PORT), "myuser", "mypassword", "ldap"
    )


@patch("safeguard.sessions.plugin.requests_tls.RequestsTLS", return_value=REQUESTS_TLS)
def test_uses_first_available_vault_address_even_if_performance_standby(_requests_tls, mocker):
    SESSION.get.side_effect = [VAULT_DOWN, PERFORMANCE_STANDBY_HEALTH_RESPONSE]
    config = create_config_and_set_loglevel(
        hashicorp_vault_config(
            address="vault.is.down,test.vault", auth_method="ldap", extra_parts="use_credential=gateway"
        )
        + HASHICORP_VAULT_APPROLE_AUTH_CONFIG
        + HASHICORP_VAULT_KV_V1_CONFIG
    )
    mocker.spy(PasswordTypeAuthenticator, "__init__")
    client = Client.create_client(config, "myuser", "mypassword")
    client.authenticator.__init__.assert_called_with(
        client.authenticator, "https://test.vault:{}".format(PORT), "myuser", "mypassword", "ldap"
    )


def create_config_and_set_loglevel(config_str):
    config = PluginConfiguration(config_str)
    log_configure(config)
    return config
