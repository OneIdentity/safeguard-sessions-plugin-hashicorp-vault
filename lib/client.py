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
from http.client import responses
import requests
import json
import abc
from safeguard.sessions.plugin.requests_tls import RequestsTLS
from safeguard.sessions.plugin.logging import get_logger
from safeguard.sessions.plugin import PluginSDKRuntimeError
from safeguard.sessions.plugin.endpoint_extractor import EndpointExtractor, EndpointException


logger = get_logger(__name__)


class VaultException(PluginSDKRuntimeError):
    pass


class InvalidConfigurationError(PluginSDKRuntimeError):
    pass


class Client:
    USABLE_HEALTH_RESPONSE_CODES = {200: "active", 473: "performance standby"}

    def __init__(self, requests_tls, authenticator, secret_retriever):
        self.__requests_tls = requests_tls
        self.__authenticator = authenticator
        self.__secret_retriever = secret_retriever

    @property
    def authenticator(self):
        return self.__authenticator

    @property
    def secret_retriever(self):
        return self.__secret_retriever

    @property
    def session_factory(self):
        return self.__requests_tls

    @staticmethod
    def token_header_from(token):
        return {"X-Vault-Token": token}

    def get_secret(self, key):
        with self.__requests_tls.open_session() as session:
            client_token = self.__authenticator.authenticate(session)
            secret = self.__secret_retriever.retrieve_secret(session, key, client_token)
        return secret

    @classmethod
    def _determine_vault_to_use(cls, requests_tls, vault_addresses, vault_port):
        vault_url = None
        with requests_tls.open_session() as session:
            for vault_address in vault_addresses:
                vault_url = "{}://{}:{}".format(
                    "https" if requests_tls.tls_enabled else "http", vault_address, vault_port
                )
                try:
                    logger.debug("Try to setup connection to Vault on address: {}".format(vault_address))
                    response = EndpointExtractor().invoke_http_method(session, vault_url + "/v1/sys/health", "get")
                    if response.status_code in cls.USABLE_HEALTH_RESPONSE_CODES:
                        logger.info(
                            'Using Vault {}; status="{}"'.format(
                                vault_url, cls.USABLE_HEALTH_RESPONSE_CODES[response.status_code],
                            )
                        )
                        break
                except EndpointException as exc:
                    raise VaultException("Connection error: {}".format(exc))
                except VaultException:
                    logger.error("Cannot connect to vault on the following address: {}".format(vault_url))
                    continue
            else:
                raise VaultException("None of the configured vaults can be reached")
        return vault_url

    @classmethod
    def create_client(cls, config, auth_username, auth_password, secrets_path=None):
        requests_tls = RequestsTLS.from_config(config)
        vault_addresses = list(map(lambda va: va.strip(), config.get("hashicorp", "address", required=True).split(",")))
        vault_port = config.getint("hashicorp", "port", default=8200)

        vault_url = cls._determine_vault_to_use(requests_tls, vault_addresses, vault_port)

        if not secrets_path:
            secrets_path = config.get("engine-kv-v1", "secrets_path")

        if secrets_path:
            secret_retriever = KVEngineV1SecretRetriever(vault_url, secrets_path)
        else:
            raise InvalidConfigurationError("No valid secrets engine can be determined based on config")

        authenticator = AuthenticatorFactory.create_authenticator(config, vault_url, auth_username, auth_password)
        return cls(requests_tls, authenticator, secret_retriever)


class AuthenticatorFactory:
    @classmethod
    def create_authenticator(cls, config, vault_url, auth_username, auth_password):
        auth_method = config.getienum(
            "hashicorp", "authentication_method", ("ldap", "userpass", "approle"), required=True
        )
        logger.debug("Authenticating to vault with method: {}".format(auth_method))
        if auth_method in ("ldap", "userpass"):
            authenticator = PasswordTypeAuthenticator(vault_url, auth_username, auth_password, auth_method)
        elif auth_method == "approle":
            role = config.get("approle-authentication", "role", required=True)
            vault_token = config.get("approle-authentication", "vault_token")
            authenticator = AppRoleAuthenticator(vault_url, vault_token, role)
        else:
            raise InvalidConfigurationError("No valid authentication method can be determined based on config")
        return authenticator


class SecretRetriever(abc.ABC):
    @abc.abstractmethod
    def retrieve_secret(self, session, key, client_token):
        raise NotImplementedError


class KVEngineV1SecretRetriever(SecretRetriever):
    def __init__(self, vault_url, secrets_path):
        self.__vault_url = vault_url
        self.__secrets_path = secrets_path

    def retrieve_secret(self, session, key, client_token):
        secret = EndpointExtractor().extract_data_from_endpoint(
            session,
            endpoint_url=self.__vault_url + "/v1/" + self.__secrets_path,
            data_path="data." + key,
            headers=Client.token_header_from(client_token),
            method="get",
        )
        return secret


class Authenticator(abc.ABC):
    @abc.abstractmethod
    def authentication_backend(self):
        raise NotImplementedError

    @abc.abstractmethod
    def authenticate(self, session):
        raise NotImplementedError


class AppRoleAuthenticator(Authenticator):
    def __init__(self, vault_url, vault_token, role):
        self.__vault_url = vault_url
        self.__vault_token = vault_token
        self.__role = role

    @property
    def authentication_backend(self):
        return "approle"

    def authenticate(self, session):
        endpoint_extractor = EndpointExtractor(self.__vault_url)
        role_id = endpoint_extractor.extract_data_from_endpoint(
            session,
            endpoint_url="/v1/auth/approle/role/" + self.__role + "/role-id",
            data_path="data.role_id",
            headers=Client.token_header_from(self.__vault_token),
            method="get",
        )
        secret_id = endpoint_extractor.extract_data_from_endpoint(
            session,
            endpoint_url="/v1/auth/approle/role/" + self.__role + "/secret-id",
            data_path="data.secret_id",
            headers=Client.token_header_from(self.__vault_token),
            method="post",
        )
        client_token = endpoint_extractor.extract_data_from_endpoint(
            session,
            endpoint_url="/v1/auth/approle/login",
            data_path="auth.client_token",
            headers=Client.token_header_from(self.__vault_token),
            method="post",
            data={"role_id": role_id, "secret_id": secret_id},
        )
        return client_token


class PasswordTypeAuthenticator(Authenticator):
    def __init__(self, vault_url, username, password, auth_backend):
        self.__vault_url = vault_url
        self.__username = username
        self.__password = password
        self.__auth_backend = auth_backend

    @property
    def authentication_backend(self):
        return self.__auth_backend

    def __calculate_endpoint(self):
        return self.__vault_url + "/v1/auth/" + self.__auth_backend + "/login/" + self.__username

    def authenticate(self, session):
        logger.debug("Performing Userpass authentication for user {}".format(self.__username))
        endpoint = self.__calculate_endpoint()
        client_token = EndpointExtractor().extract_data_from_endpoint(
            session,
            endpoint_url=endpoint,
            data_path="auth.client_token",
            method="post",
            data={"password": self.__password},
        )
        return client_token
