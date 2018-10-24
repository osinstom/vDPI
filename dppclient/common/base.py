import requests

from abc import abstractmethod


class BaseClient(object):

    def __init__(self, auth, endpoint):
        self.authenticator = auth
        self.endpoint = endpoint

    def send_get(self, path):
        url = "%s/%s" % (self.endpoint, path)
        return requests.get(url=url, headers=self._get_headers())

    def send_post(self, path, data=None):
        url = "%s/%s" % (self.endpoint, path)
        return requests.post(url, headers=self._get_headers(), data=data)

    def send_put(self, path, data=None):
        url = "%s/%s" % (self.endpoint, path)
        return requests.put(url, headers=self._get_headers(), data=data)

    def send_delete(self, path):
        url = "%s/%s" % (self.endpoint, path)
        return requests.delete(url, headers=self._get_headers())

    @abstractmethod
    def list(self):
        pass

    @abstractmethod
    def get(self):
        pass

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def update(self):
        pass

    @abstractmethod
    def delete(self):
        pass

    def _get_headers(self):
        token = self.authenticator.authenticate()
        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': token
        }
        return headers