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
def hc_address(site_parameters):
    return site_parameters['address']


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
def hc_config_engine_kv_v1(site_parameters):
    yield dedent("""
        [hashicorp_vault]
        address = {address}
        port = {port}

        [hashicorp_vault_approle_authentication]
        role = {role}
        vault_token = {vault_token}

        [hashicorp_vault_secrets_engine_kv_v1]
        secrets_path = {secrets_path}
    """.format(
        address=site_parameters['address'],
        port=site_parameters['port'],
        role=site_parameters['role'],
        vault_token=site_parameters['vault_token'],
        secrets_path=site_parameters['secrets_path'],
    ))
