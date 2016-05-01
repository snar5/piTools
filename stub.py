#from scapy_ex import *
from scapy.all import *
import binascii
import operator
import struct 

interface = 'wlan0'
probeReqs = {}
count = 0 
bssid = '00:1E:F7:75:2C:A1' 


subtypes = { 0 : "Assoc Request",
		1: "Assoc Response",
		2:"Reassoc Request",
		3:"Reassoc Response",
		4:"Probe Request",
		5:"Probe Response",
		8:"Beacon", 
		10:"Disassociate",
		11:"Authentication",
		12:"DeAuthentication",
		29:"ACK",
		40:"QOS"
	}
types = { 0:"Management", 
	  1:"Control",
	  2:"Data"
	}


def sniffProbe(p):
	global count

	if p.haslayer(Dot11):
		try:
			#if (p.type == 0) and (p.subtype != 8):
				#print "Client Request %s %s %s %s %s" % (types[p.type],subtypes[p.subtype],p.addr1,p.addr2,p.addr3)
			if (p.type == 1 and p.subtype == 11):
				print "Authentication Packet %s %s %s" % (p.addr1,p.addr2,p.addr3) 
			if (p.type ==1 and p.subtype == 12):
				print "DeAuthentication Packet %s %s %s" % (p.addr1,p.addr2,p.addr3) 
			#if (p.type in types) and (p.subtype in subtypes):
				#pass
				#print "Type %s : %s %s %s %s" % (types[p.type],subtypes[p.subtype],p.addr1,p.addr2,p.addr3)
		except Exception, e:
			print "%s Got %s %s" % (e,p.type, p.subtype)
sniff(iface=interface,store=0,count=0, prn=sniffProbe)

def sentPacket(p, bssid, station):
	ret = (p.FCfield & 0x01 == 1) and (p.addr1 == bssid) and (p.addr2 == station) # FCfield & 0x01 checks to-DS
	return ret


def APsentPacket(p, bssid, station):
	# FCfield & 0x00 checks STA to STA or management or control frame
	ret = (p.FCfield & 0x00 == 0) and (p.addr1 == station) and (p.addr2 ==  bssid) and (p.addr3 == bssid)
	return ret


def receivedPacket(p, bssid, station):
	ret = (p.FCfield & 0x01 == 1) and (p.addr1 == bssid) and (p.addr3 == station) # FCfield & 0x01 checks to-DS
	return ret


def forwardedSentPacket(p, bssid, station):
	ret = (p.FCfield & 0x02 == 2) and (p.addr3 == station) and (p.addr2 == bssid) # FCfield & 0x02 checks from-DS
	return ret


def forwardedReceivedPacket(p, bssid, station):
	ret = (p.FCfield & 0x02 == 2) and (p.addr1 == station) and (p.addr2 == bssid) # FCfield & 0x02 checks from-DS
	return ret

