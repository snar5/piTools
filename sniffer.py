#!/usr/bin/env python

from scapy.all import *
from threading import Thread
from Queue import Queue, Empty
from os import system

ap_list = {}
stop_capture = False

global cli_mode # Used if running from command line  
#--------------------------------------------------
#
# General Scanning Packet Handling 
# packetHandler gets every packet from startSniff
# 
# note: sniff_run needs to be a function to pass to the sniff
#       in order to stop it from running 

def packetHandler(pkt) :

	if pkt.haslayer(Dot11) :

  		if pkt.type == 0 and pkt.subtype == 8 :
                    channel = int(ord(pkt[Dot11Elt:3].info))
                    name = pkt.info
                    if name == "":
                        name = "Hidden"
                    power = 256 - int(ord(pkt[RadioTap].notdecoded[26]))
                    if not pkt.addr2 in list(ap_list.keys()):
                        ap_list[pkt.addr2]={}
                        ap_list[pkt.addr2]['name'] = name
                        ap_list[pkt.addr2]['channel']= channel
                        ap_list[pkt.addr2]['power'] = power 
                        ap_list[pkt.addr2]['essid'] = pkt.addr2
                        ap_list[pkt.addr2]['data'] = 0
                if pkt.type == 2: # Type 2 = Data Packets 
                    if pkt.addr2 in list(ap_list.keys()):
                        ap_list[pkt.addr2]['data'] += 1

def startSniff(interface):
    global ap_list
    global stop_capture
    stop_capture = False
    print "Sniffer Started.."
    sniff(iface=interface, store =0,count=0,stop_filter=sniff_run, prn = packetHandler)
    ap_list=[]
    print "Sniffer Stopped.."

#----------------------------------------------------------
#
#  Shared Methods between both scanning types and 
#  generally used for status and global start/stop functions
#
#------------------------------------------------------------

def show():
    return sorted(ap_list.values())

def stopSniff():
    global stop_capture
    stop_capture = True

def sniff_run(pkt):
    return stop_capture


#-----------------------------------------
#
# Single Sniff Mode Items Here 
#
#-----------------------------------------

wpa_handshake = []

# Capture EAPOL Messages 
def capture_auth(name):
    print "Name: " + name
    def packet_auth(packet):
        global stop_capture
        if packet.haslayer(EAPOL) and packet.type ==2:
            wpa_handshake.append(packet)
            print "Caught %d packet(s)" % len(wpa_handshake) 
            if len(wpa_handshake) >= 4:
                print "File Created"
                wrpcap(str(name) + ".pcap",wpa_handshake)
                stop_capture = True
                print name
    return packet_auth

# Sniff for Authentication messages call capture_auth    
def startAuthSniffSingleChannel(interface,channel,essid,name):
    global stop_capture
    stop_capture = False
    print "Attempting to Capture Auth Messages on %s channel %s for %s" %( interface,channel,essid)
    system("iwconfig %s channel %d" % (interface,int(channel)))
    essid = str(essid)
    sniff(iface=interface,lfilter= lambda x: x[Dot11].addr2 == essid or x[Dot11].addr3 == essid, store =0,count=0,stop_filter=sniff_run, prn = capture_auth(name))

# Detailed information scan 
def startDetailSniffSingleChannel(interface,channel,essid,name):
    global stop_capture
    stop_capture = False
    print "Starting single channel on %s %s %s" %( interface,channel,essid)
    system("iwconfig %s channel %d" % (interface,int(channel)))
    essid = str(essid)
    ap_list = {} # Clear to fill up with our new details
    sniff(iface=interface,lfilter= lambda x: x[Dot11].addr2 == essid or x[Dot11].addr3 == essid, store =0,count=0,stop_filter=sniff_run, prn = capture_detail(essid))

def capture_detail(essid):
    def packet_detail(pkt):

        if not pkt.addr3 in list(ap_list.keys()) and pkt.addr3 != essid:
            ap_list[pkt.addr3]={}
            ap_list[pkt.addr3]['essid'] = pkt.addr3

    return packet_detail


if __name__=="__main__":
    global cli_mode
    cli_mode = True
    capture()


