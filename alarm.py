#!/usr/bin/python3

from scapy.all import *
import base64
import argparse

count = 0
ftp_usernames = []
ftp_passwords = []

# Manipulates a packet with HTTP Basic Authorization so that only username and 
# password is read
def HTTP_string_manipulate(http_string):
  http_string = http_string.split("Authorization: Basic")[1].strip() # removes any information before username/password
  
  if "\n" in http_string: # removes any information that comes after username/password
    http_string = http_string.split("\n")[0].strip()
  
  http_string = http_string + "=" # padding for base64 decoding
  
  http_string = base64.b64decode(http_string) # decoding into bytes
  http_string = http_string.decode("utf-8") # decoding to string
  
  print(http_string)
 
# Manipulates a packet with FTP so that only username and password is read
def FTP_string_manipulate(ftp_string):
  print(ftp_string)

# Manipulates a packet with IMAP so that only username and password is read
def IMAP_string_manipulate(imap_string):
  imap_string = imap_string.split("LOGIN ")[1].strip() # removes any information before username/password
  
  if "\n" in imap_string: # removes any information that comes after username/password
    imap_string = imap_string.split("\n")[0].strip()
  
  print(imap_string)
    
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
      
    raw_data = str(packet)      
    if "nikto" in raw_data.lower(): # detects a Nikto scan
      count = count + 1
      print("ALERT #%i: Nikto scan is detected from %s (%s)!" % (count, packet[IP].src, packet.sport))
    
    if packet[TCP].dport == 21: # FTP username and password sniff
      payload = (packet[TCP].load.decode("ascii").strip())
      if "USER " in payload or "PASS " in payload:
        count = count + 1
        print(count)
        FTP_string_manipulate(payload)
    
    if packet[TCP].dport == 80: # HTTP username and password sniff
      payload = (packet[TCP].load.decode("ascii").strip())
      if "Authorization:" in payload:
        count = count + 1
        print(count)
        HTTP_string_manipulate(payload)
        
    if packet[TCP].dport == 143: # IMAP username and password sniff
      payload = (packet[TCP].load.decode("ascii").strip())
      if "LOGIN" in payload:
        count = count + 1
        print(count)
        IMAP_string_manipulate(payload)    
          
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