#!/usr/bin/env python

from scapy.all import *
from threading import Thread
from Queue import Queue, Empty


ap_list = {}
stop_sniff = True

    
def keep_sniffing(ptk):
    return stop_sniff

def action_PacketHandler(pkt) :

	if pkt.haslayer(Dot11) :
  		if pkt.type == 0 and pkt.subtype == 8 :
                    ap_list[pkt.addr2] = pkt.info
			
def show():
    return ap_list

def action_StopSniff():
    global stop_sniff 
    global ap_list
    stop_sniff = True
    ap_list= []
def capture(q):
    global stop_sniff 
    stop_sniff = False
    sniff(iface="wlan0", store =0,stop_filter=keep_sniffing, prn = action_PacketHandler)


