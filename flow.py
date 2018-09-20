
class Flow(object):

    def __init__(self, **kwargs):
        self.src_ip = kwargs['src_ip']
        self.dst_ip = kwargs['dst_ip']
        self.src_port = kwargs['src_port']
        self.dst_port = kwargs['dst_port']
