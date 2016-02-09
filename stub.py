#from scapy_ex import *
from scapy.all import *
import binascii

interface = 'wlan0mon'
probeReqs = []

def sniffProbe(p):

    if p.haslayer(Dot11Elt):
        if p.type ==0 and p.subtype ==8:
            channel = int(ord(p[Dot11Elt:3].info))
            
            print "Info: %s %s" % (channel, p[Dot11Elt:].info)
            print len(p[RadioTap].notdecoded)
            extra = 256-int(ord(p[RadioTap].notdecoded[26]))
            print extra
            
sniff(iface=interface,store=0,count=0,prn=sniffProbe)

