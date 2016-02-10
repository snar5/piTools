#from scapy_ex import *
from scapy.all import *
import binascii
import operator

interface = 'wlan0mon'
probeReqs = {}

def sniffProbe(p):
    global probeReqs
    if p.haslayer(Dot11Elt):
        if p.type ==0 and p.subtype ==8:
            		channel = int(ord(p[Dot11Elt:3].info))
            		name = p.info
			power = 256 - int(ord(p[RadioTap].notdecoded[26]))
			msg = "AP: %s Pwer: %s Channel: %s" % (name,power,channel)
                        if not p.addr2 in list(probeReqs.keys()):
                            #probeReqs['mac'] = p.addr2
                            probeReqs[p.addr2]={}
                            probeReqs[p.addr2]['channel'] = channel
                            probeReqs[p.addr2]['name'] = name
		            probeReqs[p.addr2]['power'] = power	
		
    x = sorted(probeReqs,key=lambda k: probeReqs[k]['power'])
    print x[k]['power']
            
sniff(iface=interface,store=0,count=0,prn=sniffProbe)

