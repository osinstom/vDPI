from dppclient.common.auth import Authenticator
from dppclient.v1.modules import Modules

class Client(object):

    def __init__(self, host_ip):
        self.authenticator = Authenticator(host_ip)
        self.modules = Modules(self.authenticator, host_ip)


