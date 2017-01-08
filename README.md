# DNSSpoof

A DNS spoofer tool written in Python3.

## How to use it?

    usage: dnsspoof.py [-h] [-d DOMAIN] [-i INTERFACE] [-t TARGET] [-r IP]
    
    optional arguments:
      -h, --help    show this help message and exit
      -d DOMAIN     Domain to spoof (default: all)
      -i INTERFACE  Interface to listen on (default: default)
      -t TARGET     Target's IP. If not specified (default: all)
      -r IP         IP to redirect the target to (default: local IP)

## Requirements

This script uses the following modules:

 - Argparse
 - Scapy
 - Threading

## How does it work?

The script will sniff the network traffic and intercept all the DNS queries matching a given domain name from the victim. Once this query is intercepted, it will forge and send a valid response with a malicious RR holding a given IP.

