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
import re
from safeguard.sessions.plugin import PluginSDKRuntimeError
from safeguard.sessions.plugin.credentialstore_plugin import CredentialStorePlugin

from .client import Client


class Plugin(CredentialStorePlugin):
    SECRET_TYPE_TO_FIELD = {
        "password": dict(option="password_field", default="password"),
        "key": dict(option="key_field", default="key")
    }

    def __init__(self, configuration):
        super().__init__(configuration)

    def do_get_password_list(self):
        try:
            secret_path, secret_field = self.secret_path_and_field(
                account=self.account, asset=self.asset, secret_type="password", user_defined_path=self.user_defined_path
            )

            vault_client = Client.create_client(self.plugin_configuration,
                                                self.connection.gateway_username,
                                                self.connection.gateway_password,
                                                secret_path)
            password = vault_client.get_secret(secret_field)
            return {'passwords': [password] if password else []}
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None

    def do_get_private_key_list(self):
        def determine_keytype(key):
            if key.startswith('-----BEGIN RSA PRIVATE KEY-----'):
                return 'ssh-rsa'
            elif key.startswith('-----BEGIN DSA PRIVATE KEY-----'):
                return 'ssh-dss'
            else:
                self.logger.error('Unsupported key type')

        def get_supported_key(key):
            return list(filter(lambda key_pair: key_pair[0], [(determine_keytype(key), key)]))

        try:
            secret_path, secret_field = self.secret_path_and_field(
                account=self.account, asset=self.asset, secret_type="key", user_defined_path=self.user_defined_path
            )

            vault_client = Client.create_client(self.plugin_configuration,
                                                self.connection.gateway_username,
                                                self.connection.gateway_password,
                                                secret_path)
            key = vault_client.get_secret(secret_field)
            return {'private_keys': get_supported_key(key) if key else []}
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving private keys: {}".format(ex))
            return None

    @property
    def user_defined_path(self):
        return self.session_cookie.get('questions', {}).get('vp')

    def secret_path_and_field(self, account, asset, secret_type, user_defined_path):
        default_field = self.plugin_configuration.get(
            'engine-kv-v1',
            self.SECRET_TYPE_TO_FIELD[secret_type]["option"],
            default=self.SECRET_TYPE_TO_FIELD[secret_type]["default"]
        )

        secret_path, secret_field = (
            self.parse_user_defined_path_and_field(user_defined_path, default_field) if user_defined_path
            else (
                '{}/{}'.format(
                    self.plugin_configuration.get('engine-kv-v1', 'secrets_path', required=True),
                    account
                ),
                default_field
            )
        )
        self.logger.info("Calculated secret path={} field={}".format(secret_path, secret_field))
        return secret_path, secret_field

    def parse_user_defined_path_and_field(self, path, default_field):
        field = default_field
        delimiter = self.plugin_configuration.get('engine-kv-v1', 'delimiter')

        match = re.search("^/(.)/(.*)", path)
        tokens = match.groups() if match else []
        if len(tokens) > 1:
            delimiter = tokens[0]
            path = tokens[1]

        if delimiter:
            elems = path.rsplit(delimiter, maxsplit=1)
            path = elems.pop(0)
            if elems:
                field = elems.pop(0)

        return path, field
