#! /usr/bin/env python2.7

from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy_http import http
from scapy_ssl_tls.ssl_tls import TLS, SSL, TLSRecord, SSLv2Record
import sys
import logging

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)


def callback(pkt):
    pkt.show() # debug statement
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            print "ENCRYPTED PACKET!"
        elif pkt.haslayer('HTTP'):
            print "HTTP"
        else:
            print "Some other packet.."


def main(intf):
    sniff(iface=intf, prn=callback, filter="tcp", store=0)


if __name__ == "__main__":
    if sys.argv[1]:
        main(sys.argv[1])
    else:
        print 'Interface name required!'
