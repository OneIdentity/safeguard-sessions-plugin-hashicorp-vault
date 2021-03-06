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
        "key": dict(option="key_field", default="key"),
    }

    def __init__(self, configuration):
        super().__init__(configuration, configuration_section="hashicorp")

    def do_get_password_list(self):
        try:
            secret_path, secret_field = self.secret_path_and_field(
                account=self.account, asset=self.asset, secret_type="password", user_defined_path=self.user_defined_path
            )

            if secret_path is None or secret_field is None:
                return {"passwords": []}

            vault_client = Client.create_client(
                self.plugin_configuration,
                self.authentication_username,
                self.authentication_password,
                secret_path,
            )
            password = vault_client.get_secret(secret_field)
            return {"passwords": [password] if password else []}
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving passwords: {}".format(ex))
            return None

    def do_get_private_key_list(self):
        def get_supported_key(key):
            return list(filter(lambda key_pair: key_pair[0], [(self.determine_key_type(key), key)]))

        try:
            secret_path, secret_field = self.secret_path_and_field(
                account=self.account, asset=self.asset, secret_type="key", user_defined_path=self.user_defined_path
            )

            if secret_path is None or secret_field is None:
                return {"private_keys": []}

            vault_client = Client.create_client(
                self.plugin_configuration,
                self.connection.gateway_username,
                self.connection.gateway_password,
                secret_path,
            )
            key = vault_client.get_secret(secret_field)
            return {"private_keys": get_supported_key(key) if key else []}
        except PluginSDKRuntimeError as ex:
            self.logger.error("Error retrieving private keys: {}".format(ex))
            return None

    @property
    def user_defined_path(self):
        return self.session_cookie.get("questions", {}).get("vp")

    def secret_path_and_field(self, account, asset, secret_type, user_defined_path):
        default_field = self.plugin_configuration.get(
            "engine-kv-v1",
            self.SECRET_TYPE_TO_FIELD[secret_type]["option"],
            default=self.SECRET_TYPE_TO_FIELD[secret_type]["default"],
        )

        secret_path, secret_field = (
            self.parse_user_defined_path_and_field(user_defined_path, default_field, secret_type)
            if user_defined_path
            else (
                "{}/{}".format(self.plugin_configuration.get("engine-kv-v1", "secrets_path", required=True), account),
                default_field,
            )
        )

        self.logger.info("Calculated secret path={} field={}".format(secret_path, secret_field))
        return secret_path, secret_field

    def parse_user_defined_path_and_field(self, path, default_field, secret_type):
        path, schema = self.get_schema(path, secret_type)

        if secret_type != schema:
            self.logger.debug(
                "User defined secret type is not equal to system requested type {}!={}".format(schema, secret_type)
            )
            return None, None

        # replace // with URL encoded version
        path = path.replace("//", "%2F")

        path, field = self.get_field(path, default_field)

        path = path.replace("##", "#")

        return path, field

    def get_schema(self, path, secret_type):
        schema = self.plugin_configuration.getienum("engine-kv-v1", "default_type", ("password", "key")) or secret_type
        match = re.match(r"(\w+)://(.*)", path)

        if not match:
            return path, schema
        if "password".startswith(match.group(1)):
            schema = "password"
        elif "key".startswith(match.group(1)):
            schema = "key"
        else:
            self.logger.warning("Invalid schema in user defined path: path={} schema={}".format(path, match.group(1)))
            return path, schema

        return match.group(2), schema

    def get_field(self, path, field):
        reverse_path = path[::-1]
        match = re.match(r"([^#]*)#($|[^#].*)", reverse_path)

        return (match.group(2)[::-1], match.group(1)[::-1]) if match else (path, field)
