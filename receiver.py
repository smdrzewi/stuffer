#!/usr/bin/python

import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

def declutter(packet):
	if(packet[TCP].reserved == 15):
		return packet[TCP].load

sniff(filter="tcp", prn=declutter)
