#!/usr/bin/env bash

echo $2 > /opt/config/dst_mac

sudo apt-get update

sudo apt-get -qq -y install python-pip git openvswitch-switch

IFACE=$(ifconfig -a | awk '/ens/ {print $1}' | sed -n 2p)

sudo pip install scapy==2.3.2
sudo pip install scapy-ssl_tls
sudo pip install scapy_http
sudo pip install netifaces
sudo pip install influxdb
sudo pip install requests

sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 ${IFACE}
sudo ovs-ofctl add-flow br0 in_port=1,actions=mod_dl_src=$1,mod_dl_dst=$2,in_port

sudo python vdpi.py ${IFACE}



