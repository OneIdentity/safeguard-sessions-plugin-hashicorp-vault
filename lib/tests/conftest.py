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
from textwrap import dedent
import pytest


@pytest.fixture
def hc_address(site_parameters):
    return site_parameters['address']


@pytest.fixture
def hc_port(site_parameters):
    return site_parameters['port']


@pytest.fixture
def hc_role(site_parameters):
    return site_parameters['role']


@pytest.fixture
def hc_vault_token(site_parameters):
    return site_parameters['vault_token']


@pytest.fixture
def hc_secret_path(site_parameters):
    return site_parameters['secrets_path']


@pytest.fixture
def hc_account(site_parameters):
    return site_parameters['account']


@pytest.fixture
def hc_account_password(site_parameters):
    return site_parameters['account_password']


@pytest.fixture
def hc_wrong_account(site_parameters):
    return site_parameters['wrong_account']


@pytest.fixture
def hc_account_with_private_key(site_parameters):
    return site_parameters['account_with_private_key']


@pytest.fixture()
def hc_account_private_key(site_parameters):
    return site_parameters['account_private_key']


@pytest.fixture()
def hc_account_with_unsupported_key(site_parameters):
    return site_parameters['account_with_unsupported_key']


@pytest.fixture
def hc_config_approle_auth_engine_kv_v1(site_parameters):
    yield dedent("""
        [hashicorp]
        address = {address}
        port = {port}
        authentication_method = approle

        [approle-authentication]
        role = {role}
        vault_token = {vault_token}

        [engine-kv-v1]
        secrets_path = {secrets_path}
    """.format(
        address=site_parameters['address'],
        port=site_parameters['port'],
        role=site_parameters['role'],
        vault_token=site_parameters['vault_token'],
        secrets_path=site_parameters['secrets_path'],
    ))


@pytest.fixture
def make_hc_config(site_parameters):
    def _make_config(auth_method, secrets_path=site_parameters['secrets_path']):
        return dedent("""
            [hashicorp]
            address = {address}
            port = {port}
            authentication_method = {auth_method}
            use_credential=explicit
            ldap_username={ldap_username}
            ldap_password={ldap_password}
            username={username}
            password={password}

            [approle-authentication]
            role = {role}
            vault_token = {vault_token}

            [engine-kv-v1]
            secrets_path = {secrets_path}
        """.format(
            address=site_parameters['address'],
            port=site_parameters['port'],
            role=site_parameters['role'],
            vault_token=site_parameters['vault_token'],
            secrets_path=secrets_path,
            ldap_username=site_parameters['ldap_username'],
            ldap_password=site_parameters['ldap_password'],
            username=site_parameters['username'],
            password=site_parameters['password'],
            auth_method=auth_method
        ))
    return _make_config
