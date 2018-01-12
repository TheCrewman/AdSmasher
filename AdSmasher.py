#!/usr/bin/python

import sys
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

whitelist = open("whitelist.conf", "rb")
whitelist_content = whitelist.read()
whitelist.close()

blacklist = open("blacklist.conf", "rb")
blacklist_content = blacklist.read()
blacklist.close()

suspicious_list = open("suspicious.conf", "ab")
tmp_list = []

def adBlocker(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNS):
        requested_host = scapy_packet[DNS][DNSRR].rrname[:len(scapy_packet[DNS][DNSRR].rrname) - 1]
        if requested_host in blacklist_content and "#%s" % (requested_host) not in blacklist_content and requested_host not in whitelist_content:
            packet.drop()
            print "[!] DNS request for %s has been dropped" % (requested_host)
        else:
            if "ad" in requested_host.lower() and requested_host not in tmp_list:
                tmp_list.append(requested_host)
                suspicious_list.write("%s\n\r" % (requested_host))
                print "[*] %s added to suspicious domains list" % (requested_host)

            packet.accept()
    else:
        packet.accept()

def main():
    os.system("clear; iptables -t filter -I INPUT -p udp --source-port 53 -j NFQUEUE --queue-num 1")

    print "[*] Listening for DNS requests..."

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, adBlocker)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        suspicious_list.close()
        os.system("iptables -t filter -D INPUT -p udp --source-port 53 -j NFQUEUE --queue-num 1")
        print "\n[*] Exiting..."
        sys.exit(0)

    nfqueue.unbind()

try:
    main()
except OSError:
    print "[!] Only root user can run this script"
    sys.exit(-1)
