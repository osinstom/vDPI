from scapy.all import *
from scapy.layers.inet import TCP, IP
import sys
import logging

from flow import Flow, L4Flow
from dppclient.client import Client

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

flows = []
pkts = 0
dpmodule_id = ''
client = Client('10.254.184.104')


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
    if pkt.haslayer(IP):
        print "Packet received: %s, %s -> %s" % (pkt[IP].proto, pkt[IP].src, pkt[IP].dst)
        global pkts
        pkts += 1


def debug_flow(pkt):
    print "New flow received: %s, %s -> %s" % (pkt[IP].proto, pkt[IP].src, pkt[IP].dst)


def push_flow_fastpath():
    client.modules.configure(id=dpmodule_id,
                             table_name='tester',
                             match_keys=["1"],
                             action_name='push_fastpath',
                             action_data=[],
                             priority=1
                             )


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
            push_flow_fastpath()
        elif pkt.haslayer('HTTP'):
            print "HTTP"
        else:
            print "Some other packet.."
    print_summary()


def print_summary():
    global pkts
    print "========  SUMMARY  ========"
    print "Number of packets received: %s, Number of unique flows: %s" % (pkts, len(flows))


def install_dpmodule():
    status, data = client.modules.create(project_id='b63b40c0afc94cb68d3db8bc13c4c189',
                                         network_id='af707ff8-d0f4-470b-8743-83e5c615ce12',
                                         name="PROGRAM1",
                                         description="Test",
                                         program="tester.p4")
    print data
    global dpmodule_id
    dpmodule_id = data['module']['id']
    print "Data plane module (vdpi.p4) for vDPI has been installed."
    resp = client.modules.attach(id=dpmodule_id,
                          chain_with="11.0.0.19",
                          protocol="icmp",
                          dst_ip="11.0.0.13/32",
                          src_ip="11.0.0.7/32"
                          )
    if resp.status_code == 201:
        print "Data plane module has been attached."


def cleanup():
    client.modules.detach(id=dpmodule_id)
    print "Data plane module (vdpi.p4) for vDPI has been detached."
    client.modules.delete(id=dpmodule_id)
    print "Data plane module (vdpi.p4) for vDPI has been removed."

def main(intf):
    install_dpmodule()
    try:
        sniff(iface=intf, prn=callback, filter="", store=0)
    except KeyboardInterrupt:
        print_summary()
    finally:
        cleanup()


if __name__ == "__main__":
    if sys.argv[1]:
        main(sys.argv[1])
    else:
        print 'Interface name required!'
