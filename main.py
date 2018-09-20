from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy_ssl_tls.ssl_tls import TLS, SSL
from scapy.layers.ssl_tls import TLSRecord, SSLv2Record

from flow import Flow

import p4client

encrypted_flows = []
flows = []


def get_flow(pkt):
    return Flow(src_ip=pkt.IP.src,
                dst_ip=pkt.IP.dst,
                src_port=pkt.TCP.src,
                dst_port=pkt.TCP.dst)


def add_to_encrypted_flows(pkt):
    encrypted_flows.append(get_flow(pkt))


def add_to_flows(pkt):
    flows.append(get_flow(pkt))


def pkt_callback(pkt):
    # pkt.show() # debug statement
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            print "ENCRYPTED PACKET!"
            add_to_encrypted_flows(pkt)
        else:
            print "HTTP"
            add_to_flows(pkt)


sniff(iface="enp0s3", prn=pkt_callback, filter="tcp", store=0)
