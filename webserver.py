# Web Server 

import web 
from web import form
import scpsniffer
from scapy.all import *
from threading import Thread
from Queue import Queue, Empty
import json 
from multiprocessing import Process
import signal 

urls = ( '/', 'index',
        '/stats','return_stats',
        '/wifi','wifi'
    )

globalStatus = {'status': scpsniffer.stop_capture,'title':'piToolBox'}

render = web.template.render('templates',base='base',globals=globalStatus)
 

class index:
    def GET(self):
        return render.index()
    def POST(self):
        return json.dumps(scpsniffer.show())
class wifi:
    def GET(self):
        return render.wifi()
    def POST(self):
        return json.dumps(scpsniffer.show())

class return_stats:
    def GET(self):
        print userData
        return render.index(scpsniffer.stop_capture,scpsniffer.show())

def thread_sniffer(q):
    scpsniffer.capture()

def create_sniffer_thread():
    q = Queue()
    threadserver = Thread(target = thread_sniffer, args=(q,))
    threadserver.daemon = True
    threadserver.start() 

# Channel hopper - This code is very similar to that found in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
def channel_hopper(interface):
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iwconfig %s channel %d" % (interface,channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break 

def stop_channel_hop(signal, frame):
    # set the stop_sniff variable to True to stop the sniffer
    channel_hop.terminate()
    channel_hop.join()
    scpsniffer.action_StopSniff()
    
if __name__== "__main__":
# 
    scpsniffer.cli_mode = False
    create_sniffer_thread()
    channel_hop = Process(target = channel_hopper,args=(args.inteface))
    channel_hop.start() 
    signal.signal(signal.SIGINT, stop_channel_hop) 
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    app.run() 

