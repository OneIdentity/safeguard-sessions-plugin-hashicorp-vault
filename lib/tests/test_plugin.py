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
from textwrap import dedent
from unittest.mock import patch

from safeguard.sessions.plugin_impl.test_utils.plugin import assert_plugin_hook_result
from ..plugin import Plugin


@pytest.fixture
def configured_plugin():
    config = dedent(
        """
        [hashicorp]
        address = test.vault
        port = 8200
        authentication_method = approle

        [approle-authentication]
        role = testrole
        vault_token = test_token

        [engine-kv-v1]
        secrets_path = kv/users
    """
    )
    return Plugin(config)


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch("lib.client.Client.get_secret", return_value="password")
def test_do_get_password_list(client, _, configured_plugin):
    username = "wsmith"
    password_list = configured_plugin.get_password_list(
        cookie=dict(), session_cookie=dict(), target_username=username, protocol="SSH"
    )
    client.assert_called_with("password")
    assert_plugin_hook_result(password_list, dict(cookie=dict(account=username, asset=None), passwords=["password"]))


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch(
    "lib.client.Client.get_secret",
    return_value=("-----BEGIN RSA PRIVATE KEY-----\n" "my key\n" "-----END RSA PRIVATE KEY-----"),
)
def test_do_get_privatekey_list(client, _, configured_plugin):
    username = "wsmith"
    password_list = configured_plugin.get_private_key_list(
        cookie=dict(), session_cookie=dict(), target_username=username, protocol="SSH"
    )
    client.assert_called_with("key")
    assert_plugin_hook_result(
        password_list,
        dict(
            cookie=dict(account=username, asset=None),
            private_keys=[
                ("ssh-rsa", ("-----BEGIN RSA PRIVATE KEY-----\n" "my key\n" "-----END RSA PRIVATE KEY-----"))
            ],
        ),
    )


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch(
    "lib.client.Client.get_secret",
    return_value=("-----BEGIN UNKNOWN PRIVATE KEY-----\n" "my key\n" "-----END UNKNOWN PRIVATE KEY-----"),
)
def test_do_get_privatekey_list_for_unsupported_private_keys(client, _, configured_plugin):
    username = "wsmith"
    private_key_list = configured_plugin.get_private_key_list(
        cookie=dict(), session_cookie=dict(), target_username=username, protocol="SSH"
    )
    client.assert_called_with("key")
    assert_plugin_hook_result(private_key_list, dict(cookie=dict(account=None, asset=None), private_keys=[]))


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch("lib.client.Client.get_secret", return_value=None)
def test_getting_password_for_unknown_user(client, _, configured_plugin):
    password_list = configured_plugin.get_password_list(
        cookie=dict(), session_cookie=dict(), target_username="unknown", protocol="SSH"
    )
    assert_plugin_hook_result(password_list, dict(cookie=dict(account=None, asset=None), passwords=[]))


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch("lib.client.Client.get_secret", return_value=None)
def test_getting_private_key_for_unknown_user(client, _, configured_plugin):
    password_list = configured_plugin.get_private_key_list(
        cookie=dict(), session_cookie=dict(), target_username="unknown", protocol="SSH"
    )
    assert_plugin_hook_result(password_list, dict(cookie=dict(account=None, asset=None), private_keys=[]))


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch("lib.client.Client.create_client")
def test_secrets_path_got_from_session_cookie(client, determine_vault_to_use, make_hc_config):
    config = make_hc_config(auth_method="ldap", secrets_path="")
    session_cookie = {"questions": {"vp": "my/path"}}
    plugin = Plugin(config)
    plugin.get_password_list(cookie={}, session_cookie=session_cookie, target_username="wsmith", protocol="SSH")
    assert session_cookie.get("questions").get("my/path") in client.call_args[0]


def provide_secret_cases():
    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
        """
        ),
        "alice",
        "10.0.0.5",
        None,
        {"password": ("kv/users/alice", "password"), "key": ("kv/users/alice", "key")},
        id="defaults",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
        """
        ),
        "alice",
        "10.0.0.5",
        "my/secret",
        {"password": ("my/secret", "password"), "key": ("my/secret", "key")},
        id="user_path",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "my/secret",
        {"password": ("my/secret", "password"), "key": (None, None)},
        id="user_path_default_type_password",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=key
        """
        ),
        "alice",
        "10.0.0.5",
        "my/secret",
        {"password": (None, None), "key": ("my/secret", "key")},
        id="user_path_default_type_key",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "p://my/secret",
        {"password": ("my/secret", "password"), "key": (None, None)},
        id="user_path_with_short_password_schema",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "password://my/secret",
        {"password": ("my/secret", "password"), "key": (None, None)},
        id="user_path_with_long_password_schema",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "k://my/secret",
        {"password": (None, None), "key": ("my/secret", "key")},
        id="user_path_with_short_key_schema",
    )

    yield pytest.param(
        dedent(
            """
                [engine-kv-v1]
                secrets_path=kv/users
                default_type=password
            """
        ),
        "alice",
        "10.0.0.5",
        "key://my/secret",
        {"password": (None, None), "key": ("my/secret", "key")},
        id="user_path_with_long_key_schema",
    )

    yield pytest.param(
        dedent(
            """
                [engine-kv-v1]
                secrets_path=kv/users
                default_type=password
            """
        ),
        "alice",
        "10.0.0.5",
        "foo://my/secret",
        {"password": ("foo:%2Fmy/secret", "password"), "key": (None, None)},
        id="user_path_with_unknown_schema",
    )

    yield pytest.param(
        dedent(
            """
                [engine-kv-v1]
                secrets_path=kv/users
                default_type=password
            """
        ),
        "alice",
        "10.0.0.5",
        "key://my//secret",
        {"password": (None, None), "key": ("my%2Fsecret", "key")},
        id="user_path_with_schema_and_literal_slash",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "my/secret#pwd",
        {"password": ("my/secret", "pwd"), "key": (None, None)},
        id="user_path_with_field",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "my/secret##pwd",
        {"password": ("my/secret#pwd", "password"), "key": (None, None)},
        id="user_path_with_literal_hash",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "password://my/secret#pwd",
        {"password": ("my/secret", "pwd"), "key": (None, None)},
        id="user_path_with_field_and_schema",
    )

    yield pytest.param(
        dedent(
            """
            [engine-kv-v1]
            secrets_path=kv/users
            default_type=password
        """
        ),
        "alice",
        "10.0.0.5",
        "password://my/secret##pwd",
        {"password": ("my/secret#pwd", "password"), "key": (None, None)},
        id="user_path_with_literal_hash_and_schema",
    )


@pytest.mark.parametrize("config,account,asset,user_path,expected", provide_secret_cases())
def test_secret_path_and_field_calculation(config, account, asset, user_path, expected):
    for secret_type in ("password", "key"):
        plugin = Plugin("[logging]\nlog_level=debug\n" + config)
        secret_path, secret_field = plugin.secret_path_and_field(
            account=account, asset=asset, secret_type=secret_type, user_defined_path=user_path
        )
        assert (secret_path, secret_field) == expected[secret_type]


@patch("lib.client.Client._determine_vault_to_use", return_vaule="https://test.vault:8200")
@patch("lib.client.Client.create_client")
def test_immediate_return_for_get_password_if_secret_path_points_to_key(
    client, determine_vault_to_use, make_hc_config, caplog
):
    config = make_hc_config(auth_method="ldap", secrets_path="")
    session_cookie = {"questions": {"vp": "k://my/path"}}
    plugin = Plugin(config)
    result = plugin.get_password_list(
        cookie={}, session_cookie=session_cookie, target_username="wsmith", protocol="SSH"
    )

    assert result["passwords"] == []
    assert "User defined secret type is not equal to system requested type key!=password" in caplog.text
