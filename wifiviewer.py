#
#  Control the hopper and sniffer 
#   
# 

import sniffer
import hopper 
import os, argparse,sys,time
from threading import Thread,Event,current_thread

# Argument Parser Section # 
parser = argparse.ArgumentParser(description='Wifi Packet capture',version="0.1")
parser.add_argument('--interface',help="Interface to capture")

if len(sys.argv) ==1:
	parser.print_help()
	sys.exit(1)

args = parser.parse_args()


def create_sniffer_thread(interface):
	threadserver = Thread(target=sniffer.startSniff,args=(interface,))
	threadserver.daemon = True
	threadserver.start() 

def create_hopper_thread(interface):
	threadserver = Thread(target=hopper.run,args=(interface,))
        threadserver.daemon = True
        threadserver.start()

def main(args):
	create_hopper_thread(args.interface)
        create_sniffer_thread(args.interface)

if __name__=="__main__": 
	os.system("clear")
	print "Wifi Capture Started version {}".format(parser.version) 
	main(args)

	
