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


@patch('lib.client.Client.get_secret', return_value='password')
def test_do_get_password_list(client):
    config = dedent('''
        [hashicorp_vault]
        address = test.vault
        port = 8200
        token = test_token
        secrets_path = /kv/users
        auth_method = approle

        [hashicorp_vault_approle_authentication]
        role = testrole
    ''')
    plugin = Plugin(config)
    username = 'wsmith'
    expected_password_list = dict(cookie=dict(account=username, assets=[None]),
                                  passwords=['password'],
                                  session_cookie=dict())
    password_list = plugin.get_password_list(cookie=dict(), session_cookie=dict(), target_username=username)
    client.assert_called_with(username)
    assert password_list == expected_password_list
