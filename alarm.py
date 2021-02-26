#!/usr/bin/python3

from scapy.all import *
import argparse

count = 0

def packetcallback(packet):
  try:
    global count
    
    if packet[TCP].flags == "": #detects a NULL scan
      count = count + 1
      print("ALERT #%i: NULL scan is detected from %s (%s)!" % (count, packet[IP].src, packet.sport))
    
    if packet[TCP].flags == "F": #detects a FIN scan
      count = count + 1
      print("ALERT #%i: FIN scan is detected from %s (%s)!" % (count, packet[IP].src, packet.sport))
      
    if packet[TCP].flags == "PFU": #detects a Xmas scan
      count = count + 1
      print("ALERT #%i: Xmas scan is detected from %s (%s)!" % (count, packet[IP].src, packet.sport))
      
    packet_data_raw = str(packet)      
    if "nikto" in packet_data_raw.lower(): # detects a Nikto scan
      count = count + 1
      print("ALERT #%i: Nikto scan is detected from %s (%s)!" % (count, packet[IP].src, packet.sport))
    
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")