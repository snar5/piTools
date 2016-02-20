#from scapy_ex import *
from scapy.all import *
import binascii
import operator
import struct 

interface = 'wlan0'
probeReqs = {}

def sniffProbe(p):
    global probeReqs

    if p.haslayer(Dot11):
            field, val = p.getfield_and_val("type")
            type_of_frame = field.i2s[val]
            if p.type == 0 and p.subtype == 8: 
                if p.haslayer(Dot11Elt):
                    channel = int(ord(p[Dot11Elt:3].info))
                    name = p[Dot11].info
                    power = 256 - int(ord(p[RadioTap].notdecoded[26]))
                    msg = "AP: %s Pwer: %s Channel: %s Type: %s" % (name,power,channel,type_of_frame)
                    if not p.addr2 in list(probeReqs.keys()):
                         probeReqs['mac'] = p.addr2
                         probeReqs[p.addr2]={}
                         #probeReqs[p.addr2]['channel'] = channel
                         probeReqs[p.addr2]['name'] = name
                         #probeReqs[p.addr2]['power'] = power
                         probeReqs[p.addr2]['data'] = 0

            if p.type == 2:
                if p.addr2 in list(probeReqs.keys()):
                    probeReqs[p.addr2]['data'] += 1

    #x = sorted(probeReqs,key=lambda k: probeReqs[k]['power'])
    print probeReqs            
sniff(iface=interface,store=0,count=0,prn=sniffProbe)

