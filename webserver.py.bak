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
        '/stats','return_stats',
        '/wifi','wifi',
        '/apDetail','apDetail',
        '/captureEapol','captureEapol',
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
        return json.dumps(sniffer.showDetail())

class captureEapol:
    def POST(self):
       
        values = web.input(essid=None,channel=None,name=None)
        essid = values['essid']
        channel = values['channel']
        name =  values['name']
        hopper.stophopper() 
        sniffer.stopSniff()
        sleep(1)
        sniffer.startSniffSingleChannel(channel,essid,name)
        print "Eapol Returned"
        return "EAPOL Captured"

class captureDetails:

    def POST(self):       
        values = web.input(essid=None,channel=None,name=None)
        essid = values['essid']
        channel = values['channel']
        name =  values['name']
        hopper.stophopper() 
        sniffer.stopSniff()
        sleep(1)
	create_detailsniff_thread(channel,essid,name)
	print "Details.."

class return_stats:
    def GET(self):
        print userData
        return render.index(sniffer.stop_capture,sniffer.show())

def create_detailsniff_thread(channel,essid,name):
	print "Interface: ", interface
	print "Creating detail scan thread"
	threadserver = Thread(target=sniffer.startDetailSniffSingleChannel, args= (interface,channel,essid,name,))
	threadserver.daemon = True
	threadserver.start() 
	print threadserver.getName()
def create_sniffer_thread(interface,type_of_scan):
	threadserver = Thread(target=sniffer.startSniff,args=(interface,type_of_scan))
	threadserver.daemon = True
	threadserver.start()
	print threadserver.getName() 


def thread_channelhopper(interface):
    hopper.run(interface)

def create_hopper_thread(interface):
    threadserver = Thread(target = thread_channelhopper,args=(interface,))
    threadserver.daemon = True
    threadserver.start()



if __name__=="__main__":
    os.system("clear")

    create_sniffer_thread(interface,1)
    create_hopper_thread(interface)
    
    sniffer.cli_mode = False
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    print "Starting WebApplication...."
    app.run() 


