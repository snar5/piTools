# Web Server 

import web 
from web import form
import sniffer
from scapy.all import *
from threading import Thread, Event, current_thread
from Queue import Queue, Empty
import json 
from multiprocessing import Process
import signal 
from time import sleep 
from os import system 
import hopper

urls = ( '/', 'index',
	'/scannerstatus','scannerstatus',
        '/stats','return_stats',
        '/wifi','wifi',
        '/apDetail','apDetail',
        '/captureDetails','captureDetails'
    )

globalStatus = {'status': sniffer.stop_capture,'title':'piToolBox'}

render = web.template.render('templates',base='base',globals=globalStatus)

interface = 'wlan0' 

class index:
    def GET(self):
        return render.index()

class wifi:
    def GET(self):
	if sniffer.sniff_filter != 0:
		sniffer.setfilter_allAP()
		return render.wifi("Loading")
	return render.wifi(json.dumps(sniffer.show()))
    def POST(self):
        if not sniffer.stop_capture:
            return json.dumps(sniffer.show())
        else:
            return "Sniffer Not Running"

class apDetail:
    def GET(self):
        wifi_info = web.input(name=None,channel=None,essid=None)
        return render.capture(wifi_info)

    def POST(self):
        return json.dumps(sniffer.showdetails())

class captureDetails:

    def POST(self):       
        values = web.input(essid=None,channel=None,name=None)
        essid = values['essid']
        channel = values['channel']
        name =  values['name']
	print "Setting Mac to %s " % essid
	sniffer.setfilter_toAP(essid)


def create_sniffer_thread(interface):
	threadserver = Thread(target=sniffer.startSniff,args=(interface,))
	threadserver.daemon = True
	threadserver.start()
	

def thread_channelhopper(interface):
    hopper.run(interface)

def create_hopper_thread(interface):
    threadserver = Thread(target = thread_channelhopper,args=(interface,))
    threadserver.daemon = True
    threadserver.start()

class scannerstatus:
	def GET(self):
		print "Sniffer = " , sniffer.sniff_filter
		return sniffer.sniff_filter
	def POST(self):
		print "Sniffer = " , sniffer.sniff_filter
		return sniffer.sniff_filter

if __name__=="__main__":
    os.system("clear")
    sniffer.setfilter_allAP()
    create_sniffer_thread(interface)
    create_hopper_thread(interface)
    web.config.debug = False    
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    print "Starting WebApplication...."
    app.run() 


