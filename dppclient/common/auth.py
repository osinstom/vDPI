import requests

KEYSTONE_URL_TEMPLATE = "http://%s/identity/v3/auth/tokens"


class Authenticator(object):

    def __init__(self, host_ip):
        self.keystone_url = KEYSTONE_URL_TEMPLATE % host_ip

    def authenticate(self):
        data = self._get_data_from_template()
        resp = requests.post(url=self.keystone_url, json=data)
        token = resp.headers['x-subject-token']
        return token

    def _get_data_from_template(self):
        return {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": "demo",
                            "domain": {"id": "default"},
                            "password": "admin"
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "name": "Default"
                        },
                        "name": "demo"
                    }
                }
            }
        }
