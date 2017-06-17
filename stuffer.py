#!/usr/bin/env python2.7

import logging
import argparse
import socket
import sys
from scapy.all import *

def Send():
	while True:
		inp = None
		logger.info('0 to exit')
		while inp == None and not inp == '0':
			inp = str(raw_input('Enter Data: '))
		if inp == '0':
			sys.exit()
		m = IP()/TCP(reserved=7L)
		pad = Padding()
		pad.load = inp
		while len(pad.load) < (60-len(m)):
			pad.load += '\x00'
		m = m/pad
			
		m.dst = args.target
		send(m)
		m.show2()

def declutter(p):
	if (p[IP].src == args.target) and (p[TCP].reserved == 7L):
		return p[Padding]

def Receive():
	logger.info('Awaiting Packets')
	sniff(filter="tcp", prn=declutter)

parser = argparse.ArgumentParser()
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument('--send', '-s', help='Send data to the target', action = 'store_true')
exclusive.add_argument('--receive', '-r', help='Receive data from the target', action = 'store_true')
parser.add_argument('target', help='Destination Server')
parser.add_argument('--verbose', '-v', help='Enable verbose logging', action='store_true')

args = parser.parse_args()

logger = logging.getLogger('Stuffer')
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('{0}[{1}%(levelname)s{0}] %(message)s'.format('\033[0;49m','\033[1;31m'))
handler.setFormatter(formatter)
logger.addHandler(handler)
if args.verbose:
	logger.setLevel(logging.DEBUG)
else:
	logger.setLevel(logging.INFO)

try:
	socket.inet_aton(args.target)
except socket.error as e:
	logger.critical(e)
	sys.exit()

if args.send:
	Send()
elif args.receive:
	Receive()
else:
	logger.critical('No command selected!')
