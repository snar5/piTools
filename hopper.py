
from time import sleep
import random
from os import system

stop_hopper = False

def run(interface):
    print "Hopper Started.."
    while not stop_hopper:
        try:
            channel = random.randrange(1,13)
            system("iwconfig %s channel %d" % (interface,channel))
            sleep(1)
            #print "Now on channel %d" % channel
        except Exception as e:
            print e
            break
    print "Hopper Stopped"

def stophopper():
    global stop_hopper
    stop_hopper = True

        

