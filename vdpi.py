from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy_http import http
import sys
import logging

from flow import Flow, L4Flow

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

flows = []
pkts = 0


def is_new_flow(pkt):
    flow = Flow(src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                proto=pkt[IP].proto)
    if flow in flows:
        return False
    return True


def add_flow(pkt):
    flow = Flow(src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                proto=pkt[IP].proto)
    flows.append(flow)


def add_l4_flow(pkt):
    flow = L4Flow(src_ip=pkt[IP].src,
                  dst_ip=pkt[IP].dst,
                  src_port=pkt[TCP].sport,
                  dst_port=pkt[TCP].dport,
                  proto=pkt[IP].proto)
    flows.append(flow)


def debug_packet(pkt):
    print "Packet received: %s, %s -> %s" % (pkt[IP].proto, pkt[IP].src, pkt[IP].dst)
    global pkts
    pkts += 1

def debug_flow(pkt):
    print "New flow received: %s, %s -> %s" % (pkt[IP].proto, pkt[IP].src, pkt[IP].dst)


def callback(pkt):
    debug_packet(pkt)

    if is_new_flow(pkt):
        debug_flow(pkt)
        add_flow(pkt)

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if is_new_flow(pkt):
            debug_flow(pkt)
            add_l4_flow(pkt)

        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            print "ENCRYPTED PACKET!"
        elif pkt.haslayer('HTTP'):
            print "HTTP"
        else:
            print "Some other packet.."
    print_summary()


def print_summary():
    global pkts
    print "SUMMARY"
    print "Number of packets received: %s, Number of unique flows: %s" % (pkts, len(flows))


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
