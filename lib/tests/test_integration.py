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
from pytest import mark
from ..plugin import Plugin
from safeguard.sessions.plugin_impl.test_utils.plugin import assert_plugin_hook_result


@mark.parametrize("auth_method", ("approle", "ldap", "userpass"))
def test_secret_retrieving(auth_method, hc_account, hc_account_password, make_hc_config):
    plugin = Plugin(make_hc_config(auth_method))

    result = plugin.get_password_list(cookie={}, session_cookie={}, target_username=hc_account, protocol="SSH")

    assert_plugin_hook_result(result, {"passwords": [hc_account_password]})


def test_get_private_key_list(make_hc_config, hc_account_with_private_key, hc_account_private_key):
    plugin = Plugin(make_hc_config("approle"))
    result = plugin.get_private_key_list(
        cookie={}, session_cookie={}, target_username=hc_account_with_private_key, protocol="SSH"
    )

    assert_plugin_hook_result(result, {"private_keys": [("ssh-rsa", hc_account_private_key)]})


def test_get_private_key_list_for_user_with_unsupported_private_key(make_hc_config, hc_account_with_unsupported_key):
    config = make_hc_config("approle", extra_conf="key_field=unsupported_key")
    plugin = Plugin(config)
    result = plugin.get_private_key_list(
        cookie={}, session_cookie={}, target_username=hc_account_with_unsupported_key, protocol="SSH"
    )

    assert_plugin_hook_result(result, {"private_keys": []})


def test_get_private_key_list_with_non_existent_key_field(make_hc_config, hc_account, caplog):
    config = make_hc_config("approle", extra_conf="key_field=does_not_exist")
    plugin = Plugin(config)
    result = plugin.get_private_key_list(cookie={}, session_cookie={}, target_username=hc_account, protocol="SSH")

    assert_plugin_hook_result(result, {"private_keys": []})

    assert "Error retrieving private keys" in caplog.text


def test_get_password_list_with_wrong_path(make_hc_config, hc_account, caplog):
    plugin = Plugin(make_hc_config("approle", secrets_path="does/not/exist"))

    result = plugin.get_password_list(cookie={}, session_cookie={}, target_username=hc_account, protocol="SSH")

    assert_plugin_hook_result(result, {"passwords": []})

    assert "Error retrieving passwords" in caplog.text
    assert "status_code='403'" in caplog.text
    assert "status_text='Forbidden'" in caplog.text
