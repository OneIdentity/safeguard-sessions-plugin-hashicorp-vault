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
from unittest.mock import patch

from ..plugin import Plugin

CONFIG = dedent('''
    [hashicorp_vault]
    address = test.vault
    port = 8200

    [hashicorp_vault_approle_authentication]
    role = testrole
    vault_token = test_token

    [hashicorp_vault_secrets_engine_kv_v1]
    secrets_path = kv/users
''')


@patch('lib.client.Client.get_secret', return_value='password')
def test_do_get_password_list(client):
    plugin = Plugin(CONFIG)
    username = 'wsmith'
    expected_password_list = dict(cookie=dict(account=username, asset=None),
                                  passwords=['password'],
                                  session_cookie=dict())
    password_list = plugin.get_password_list(cookie=dict(), session_cookie=dict(), target_username=username)
    client.assert_called_with(username)
    assert password_list == expected_password_list


@patch('lib.client.Client.get_secret', return_value=None)
def test_getting_password_for_unknown_user(client):
    plugin = Plugin(CONFIG)
    expected_password_list = dict(cookie=dict(account=None, asset=None),
                                  passwords=[],
                                  session_cookie=dict())
    password_list = plugin.get_password_list(cookie=dict(), session_cookie=dict(), target_username='unknown')
    assert password_list == expected_password_list
