#!/usr/bin/env python

from scapy.all import *
from threading import Thread
from Queue import Queue, Empty
#import scapy_ex

ap_list = {}
stop_capture = True
global cli_mode # Used if running from command line  
    
def keep_sniffing(pkt):
    return stop_capture

def action_PacketHandler(pkt) :

	if pkt.haslayer(Dot11) :
  		if pkt.type == 0 and pkt.subtype == 8 :
                    if "\x00" in pkt.info:
                        ap_list[pkt.addr1] = "Hidden"
		    channel = int(ord(pkt[Dot11Elt:3].info))
                    name = pkt.info
                    power = 256 - int(ord(pkt[RadioTap].notdecoded[26]))
		    rate = ord(pkt[RadioTap].notdecoded[20])
                    msg = "%s Power: <b>%s</b> Channel:<b> %s</b> %s" % (name,power,channel,rate)
                    ap_list[pkt.addr2] = msg
		    pkt.show()

def show():
    return ap_list

def action_StopSniff():
    global stop_capture
    global ap_list
    stop_capture = True
    ap_list= []

def capture():
    global stop_capture
    stop_capture = False
    sniff(iface="wlan0mon", store =0,count=0,stop_filter=stop_capture, prn = action_PacketHandler)

if __name__=="__main__":
    global cli_mode
    cli_mode = True
    capture()


