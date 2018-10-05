from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy_http import http
from scapy_ssl_tls.ssl_tls import TLS, SSL, TLSRecord, SSLv2Record
from scapy.layers.ssl_tls import TLS, SSL, TLSRecord, SSLv2Record
import sys
import logging

from flow import Flow

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

flows = []


def is_new_flow(pkt):
    return True


def add_flow(pkt):
    flow = Flow()
    flows.append(flow)


def debug_packet(pkt):
    print "Packet received: %s, %s -> %s" % (pkt[IP].proto, pkt[IP].src, pkt[IP].dst)


def callback(pkt):
    debug_packet(pkt)
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if is_new_flow(pkt):
            add_flow(pkt)

        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            print "ENCRYPTED PACKET!"
        elif pkt.haslayer('HTTP'):
            print "HTTP"
        else:
            print "Some other packet.."


def print_summary():
    print "SUMMARY"


def main(intf):
    try:
        sniff(iface=intf, prn=callback, filter="", store=0)
    except KeyboardInterrupt:
        print_summary()


if __name__ == "__main__":
    if sys.argv[1]:
        main(sys.argv[1])
    else:
        print 'Interface name required!'
