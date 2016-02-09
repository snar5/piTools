#from scapy_ex import *
from scapy.all import *
import binascii

interface = 'wlan0mon'
probeReqs = []

def sniffProbe(p):

    if p.haslayer(Dot11Elt):
        if p.type ==0 and p.subtype ==8:
            channel = int(ord(p[Dot11Elt:3].info))
            print "Info: %s %s" % (channel, p.info)
            extra = p.notdecoded
            rssi = binascii.hexlify(extra)

            print binascii.b2a_uu(rssi)
            print p.name 
sniff(iface=interface,store=0,count=0,prn=sniffProbe)

