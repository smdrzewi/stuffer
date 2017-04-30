#!/usr/bin/python

import logging
#logging.getLogger("scapy").setLevel(logging.DEBUG)

from scapy.all import *

def sendall(message):
	m = IP()/TCP()
	m.dst = "172.16.208.169"
	m[TCP].reserved = 111
	pad = Padding()
	pad.load = message
	m = m/pad
	send(m)
	print("Sent %s\n" % message)
	return


print("----------------------")
print("| Welcome to Stuffer |")
print("----------------------")
print("By: Sean Drzewiecki &")
print("    Aaron Gudrian")
while True:
	sendall(str(raw_input("Enter stuffing: ")))
