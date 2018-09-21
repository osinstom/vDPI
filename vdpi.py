#! /usr/bin/env python2.7

from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy_ssl_tls.ssl_tls import TLS, SSL
from scapy.layers.ssl_tls import TLSRecord, SSLv2Record
import subprocess
from netfilterqueue import NetfilterQueue
import socket
from pprint import pprint
import json
import os
import sys
import logging

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

try:
    QUEUE_NUM = int(os.getenv('QUEUE_NUM', 1))
except ValueError as e:
    sys.stderr.write('Error: env QUEUE_NUM must be integer\n')
    sys.exit(1)


def configure_iptables():
    os.system("iptables -t raw -A PREROUTING -p tcp -j NFQUEUE --queue-num 1")


def callback(payload):
    # pkt.show() # debug statement
    data = payload.get_payload()
    pkt = IP(data)
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            print "ENCRYPTED PACKET!"
        else:
            print "HTTP"
    pkt.show2()
    payload.set_payload(str(pkt))
    print 'Sending packet... \n'
    payload.accept()
    send(pkt)

configure_iptables()

sys.stdout.write('Listening on NFQUEUE queue-num %s... \n' % str(QUEUE_NUM))
nfqueue = NetfilterQueue()
nfqueue.bind(QUEUE_NUM, callback)
s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
try:
    nfqueue.run_socket(s)
except KeyboardInterrupt:
    sys.stdout.write('Exiting \n')

s.close()
nfqueue.unbind()