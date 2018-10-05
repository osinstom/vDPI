
class Flow(object):

    def __init__(self, **kwargs):
        if kwargs:
            self.src_ip = kwargs['src_ip']
            self.dst_ip = kwargs['dst_ip']
            self.proto = kwargs['proto']

    def __str__(self):
        return "%s %s %s" % (self.src_ip, self.dst_ip, self.proto)

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(other, Flow):
            return self.src_ip == other.src_ip and self.dst_ip == other.dst_ip and self.proto == other.proto
        return False


class L4Flow(Flow):

    def __init__(self, **kwargs):
        if kwargs:
            self.src_port = kwargs['src_port']
            self.dst_port = kwargs['dst_port']
        super(L4Flow).__init__(**kwargs)

    def __str__(self):
        return "%s %s %s %s %s" % (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)