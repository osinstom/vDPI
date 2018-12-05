from scapy.all import *
from scapy.layers.inet import TCP, IP
import sys
import logging
import time
from scapy_http import http

from flow import Flow, L4Flow
from dppclient.client import Client
from influxdb import InfluxDBClient
import netifaces as ni

VDPI_PROGRAM = "vdpi.p4"

numberOfHTTPPackets = 0
numberOfEncryptedHTTPPackets = 0
numberOfRawHTTPPackets = 0
numberOfHTTPFlows = 0
numberOfEncryptedHTTPFlows = 0
numberOfRawHTTPFlows = 0
numberOfUniqueFlows = 0

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)

flows = []
pkts = 0
dpmodule_id = ''
client = None

influx_client = None


def init_clients(os_addr, influx_addr):
    global client
    client = Client(os_addr)
    global influx_client
    influx_client = InfluxDBClient(influx_addr, 8086, 'admin', '!@webrtc34', 'p4vdpi')


def get_value_from_file(filename):
    file = open(filename, "r")
    for line in file:
        return line.rstrip('\n')

network_id = get_value_from_file('/opt/config/network_id')
project_id = get_value_from_file('/opt/config/project_id')
srv_mac = get_value_from_file('/opt/config/server_dst_mac')
client_ip = get_value_from_file('/opt/config/client_ip')
server_ip = get_value_from_file('/opt/config/server_ip')

def is_new_flow(pkt):
    flow = L4Flow(src_ip=pkt[IP].src,
                  dst_ip=pkt[IP].dst,
                  src_port=pkt[TCP].sport,
                  dst_port=pkt[TCP].dport,
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


def push_flow_fastpath(src_ip, dst_ip, ip_proto, src_port, dst_port, dst_mac):
    client.modules.configure(id=dpmodule_id,
                             table_name='vdpi',
                             match_keys=[src_ip, dst_ip, ip_proto, src_port, dst_port],
                             action_name='push_fastpath',
                             action_data= [dst_mac],
                             priority=1
                             )


def report():
    measurement = [
        {
            "measurement": "statistics",
            "tags": {

            },
            "fields": {
                "numberOfPackets": numberOfHTTPPackets,
                "numberOfEncryptedPackets": numberOfEncryptedHTTPPackets,
                "numberOfRawPackets": numberOfRawHTTPPackets,
                "numberOfFlows": numberOfHTTPFlows,
                "numberOfEncryptedFlows": numberOfEncryptedHTTPFlows,
                "numberOfHTTPFlows": numberOfRawHTTPFlows
            }
        }
    ]
    influx_client.write_points(measurement)


def incrementNumberOfEncryptedPackets():
    global numberOfEncryptedHTTPPackets
    numberOfEncryptedHTTPPackets += 1


def incrementNumberOfTotalPackets():
    global numberOfHTTPPackets
    numberOfHTTPPackets += 1


def incrementNumberOfRawPackets():
    global numberOfRawHTTPPackets
    numberOfRawHTTPPackets += 1


def incrementNumberOfEncryptedFlows():
    global numberOfEncryptedHTTPFlows
    numberOfEncryptedHTTPFlows += 1


def incrementNumberOfRawFlows():
    global numberOfRawHTTPFlows
    numberOfRawHTTPFlows += 1

def incrementNumberOfFlows():
    global numberOfHTTPFlows
    numberOfHTTPFlows += 1

def callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt.haslayer(TLSRecord) or pkt.haslayer(SSLv2Record):
            incrementNumberOfEncryptedPackets()
            incrementNumberOfTotalPackets()
            if is_new_flow(pkt):
                add_l4_flow(pkt)
                incrementNumberOfFlows()
                incrementNumberOfEncryptedFlows()
                push_flow_fastpath(src_ip=pkt[IP].src,
                                   dst_ip=pkt[IP].dst,
                                   ip_proto="{}".format(pkt[IP].proto),
                                   src_port="{}".format(pkt[TCP].sport),
                                   dst_port="{}".format(pkt[TCP].dport),
                                   dst_mac=srv_mac)

        elif pkt.haslayer('HTTP'):
            incrementNumberOfRawPackets()
            incrementNumberOfTotalPackets()
            if is_new_flow(pkt):
                add_l4_flow(pkt)
                incrementNumberOfRawFlows()
                incrementNumberOfFlows()
    report()

def print_summary():
    global pkts
    print "========  SUMMARY  ========"
    print "Number of packets received: %s, Number of unique flows: %s" % (pkts, len(flows))


def _get_ipaddr_of_intf(intf):
    return ni.ifaddresses(intf)[ni.AF_INET][0]['addr']

def install_dpmodule(intf):
    status, data = client.modules.create(project_id=project_id,
                                         network_id=network_id,
                                         name="PROGRAM1",
                                         description="Test",
                                         program=VDPI_PROGRAM)
    print data
    global dpmodule_id
    dpmodule_id = data['module']['id']
    print "Data plane module (vdpi.p4) for vDPI has been installed."
    resp = client.modules.attach(id=dpmodule_id,
                          chain_with=_get_ipaddr_of_intf(intf), ## attach with vDPI itself
                          protocol="tcp", ### this vDPI is dedicated to HTTP traffic
                          dst_ip="{}/32".format(server_ip),
                          src_ip="{}/32".format(client_ip)
                          )
    if resp.status_code == 201:
        print "Data plane module has been attached."


def cleanup():
    client.modules.detach(id=dpmodule_id)
    print "Data plane module (vdpi.p4) for vDPI has been detached."
    time.sleep(3)
    client.modules.delete(id=dpmodule_id)
    print "Data plane module (vdpi.p4) for vDPI has been removed."

def main(intf, os_addr, influx_addr):
    init_clients(os_addr, influx_addr)
    install_dpmodule(intf)
    try:
        sniff(iface=intf, prn=callback, filter="", store=0)
    except KeyboardInterrupt:
        print_summary()
    finally:
        cleanup()


if __name__ == "__main__":
    if not sys.argv[1]:
        print 'Interface name required!'
    if not sys.argv[2]:
        print 'OpenStack IP address required'
    if not sys.argv[3]:
        print 'InfluxDB IP address required'
    main(sys.argv[1], sys.argv[2], sys.argv[3])