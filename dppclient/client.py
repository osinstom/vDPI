from dppclient.common.auth import Authenticator
from dppclient.v1.modules import Modules

NEUTRON_URL = 'http://10.254.188.152:9696/v2.0'


class Client(object):

    def __init__(self, host_ip):
        self.authenticator = Authenticator(host_ip)
        self.modules = Modules(self.authenticator, host_ip)


