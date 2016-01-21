# Web Server 

import web 
from web import form
import scpsniffer
from scapy.all import *
from threading import Thread
from Queue import Queue, Empty
import json 

urls = ( '/', 'index',
        '/stats','return_stats',
        '/wifi','wifi'
    )

globalStatus = {'status': scpsniffer.stop_sniff,'title':'piToolBox'}

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
        return render.index(scpsniffer.stop_sniff,scpsniffer.show())

def thread_sniffer(q):
    scpsniffer.capture(q)

def create_sniffer_thread():
    q = Queue()
    threadserver = Thread(target = thread_sniffer, args=(q,))
    threadserver.daemon = True
    threadserver.start() 

if __name__== "__main__":
    create_sniffer_thread()
    app = web.application(urls, globals())
    app.internalerror = web.debugerror
    app.run() 

