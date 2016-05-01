#!/usr/bin/env python

from scapy.all import *
from threading import Thread
from Queue import Queue, Empty
from os import system

wifi_list = {}
stop_capture = False
sniff_filter = 0 
apMac = '' 

#--------------------------------------------------
#
# General Scanning Packet Handling 
# packetHandler gets every packet from startSniff
# 
# note: sniff_run needs to be a function to pass to the sniff
#       in order to stop it from running 
# -------------------------------------------------



def packetHandler(pkt):
	name = ""
	if sniff_filter == 0:
		if pkt.type == 0 and (pkt.subtype == 8 or pkt.subtype == 5):
			bssid = pkt[Dot11].addr3
			if bssid in wifi_list:
				return 
			p = pkt[Dot11Elt]
			cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
						"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    
			ssid, channel = None, None 
			crypto = set() 
			while isinstance(p, Dot11Elt):
				if p.ID == 0:
					ssid = p.info
				elif p.ID ==3:
					channel = ord(p.info)
				elif p.ID == 48:
					crypto.add("WPA2")
				elif p.ID == 221 and p.info.startswith('\x00p\xf2\x01\x01\x00'):
					crypto.add("WPA")
				p = p.payload 
			if not crypto:
				if 'privacy' in cap:
					crypto.add("WEP")
				else:
					crypto.add("OPN")
			power = 256 - int(ord(pkt[RadioTap].notdecoded[26]))
			wifi_list[bssid]={}
			wifi_list[bssid]['name'] = ssid
			wifi_list[bssid]['channel']= channel
			wifi_list[bssid]['power'] = power 
			wifi_list[bssid]['essid'] = pkt.addr3
			wifi_list[bssid]['data'] = 0
			wifi_list[bssid]['clients'] = {}
			wifi_list[bssid]['enc'] = '/'.join(crypto)

		if pkt.type == 2: # Type 2 = Data Packets
			if pkt.addr2 in list(wifi_list.keys()):
				wifi_list[pkt.addr2]['data'] += 1

		if pkt.addr1 in list(wifi_list) and (pkt.FCfield & 0x01 ==1):
			if pkt.addr2 not in wifi_list[pkt.addr1]['clients']:
				wifi_list[pkt.addr1]['clients'][pkt.addr2] = pkt.addr2

	if sniff_filter == 1:
		if pkt.addr1 == apMac.lower() and (pkt.FCfield & 0x01 ==1):
			wifi_list[pkt.addr2]['client'][pkt.addr2]
			wifi_list[pkt.addr2]['power'] = 256 - int(ord(pkt[RadioTap].notdecoded[26]))
				
 
def startSniff(interface):
	global wifi_list
    	global stop_capture
	sniff_filter = ''
    	stop_capture = False
   	wifi_list = {}
	#Sniff Routine 
    	sniff(iface=interface,store =0,count=0,stop_filter=run(), prn = packetHandler)
  

def show():
    if len(wifi_list) > 0:
	return sorted(wifi_list.values())
    else:
	return None

def showdetails():
	if len(wifi_list) > 0:
		return sorted(wifi_list.values())
	else:
		return None
def stop():
    global stop_capture
    stop_capture = True

def run():
    return stop_capture

def setfilter(filtertxt=''):
	global sniff_filter
	sniff_filter = filtertxt

def setfilter_toAP(APMac):
	global sniff_filter
	global wifi_list
	global apMac 
	sniff_filter = 1
	apMac = APMac.lower() 
	wifi_list = {}
	print "Setting filter to 'toAP' %s" % apMac

def setfilter_allAP():
	global wifi_list
	global sniff_filter
	wifi_list={}
	sniff_filter = 0
	print "Setting filter to 'All'"


