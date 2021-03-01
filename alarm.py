#!/usr/bin/python3

from scapy.all import *
import base64
import socket
import argparse

count = 0
usernames = []
passwords = []

# Manipulates a packet with HTTP Basic Authorization so that only username and 
# password is read. Returns the manipulated http_string with contains both
# username and password.
def HTTP_string_manipulate(http_string):
    http_string = http_string.split("Authorization: Basic")[1].strip() # removes any information before username/password
  
    if "\n" in http_string: # removes any information that comes after username/password
      http_string = http_string.split("\n")[0].strip()
  
    http_string = http_string + "=" # padding for base64 decoding
  
    http_string = base64.b64decode(http_string) # decoding into bytes
    http_string = http_string.decode("utf-8") # decoding to string
  
    return http_string

# Final manipulation of string to get both username and password of HTTP
# Basic Authentication and prints out the credentials
def HTTP_credentials(http_creds, ip_addr_src, ip_addr_dst, port):
    username = http_creds.split(":")[0].strip()
    password = http_creds.split(":")[1].strip()
    port = socket.getservbyport(port)
    print("ALERT #%i: Usernames and passwords sent in-the-clear from %s to %s (%s) (username:%s, password:%s)" % (count, ip_addr_src, ip_addr_dst, port, username, password))

# Manipulates a packet with IMAP so that only username and password is read.
# Returns the IMAP string which contains both username and password
def IMAP_string_manipulate(imap_string):
    imap_string = imap_string.split("LOGIN ")[1].strip() # removes any information before username/password
  
    if "\n" in imap_string: # removes any information that comes after username/password
        imap_string = imap_string.split("\n")[0].strip()
  
    return imap_string
    
# Final manipulation of string to get both username and password of IMAP
# and prints out the credentials
def IMAP_credentials(imap_creds, ip_addr_src, ip_addr_dst, port):
    username = imap_creds.split(" ")[0].strip()
    password = imap_creds.split(" ")[1].strip()
    port = socket.getservbyport(port)
    print("ALERT #%i: Usernames and passwords sent in-the-clear from %s to %s (%s) (username:%s, password:%s)" % (count, ip_addr_src, ip_addr_dst, port, username, password))

# Main function that sniffs through the packets to search for null, fin, xmas, 
# and nikto scans, SMB protocols, and if there is any existence of usernames
# and passwords caught through FTP, HTTP Basic Authentication, and IMAP
def packetcallback(packet):
    try:
        global count
    
        if packet[TCP].flags == "": # detects a NULL scan
            count = count + 1
            print("ALERT #%i: NULL scan is detected from %s to %s (%s)!" % (count, packet[IP].src, packet[IP].dst, packet.dport))
    
        if packet[TCP].flags == "F": # detects a FIN scan
            count = count + 1
            print("ALERT #%i: FIN scan is detected from %s to %s (%s)!" % (count, packet[IP].src, packet[IP].dst, packet.dport))
      
        if packet[TCP].flags == "PFU": # detects a Xmas scan
            count = count + 1
            print("ALERT #%i: Xmas scan is detected from %s to %s (%s)!" % (count, packet[IP].src, packet[IP].dst, packet.dport))
      
        raw_data = str(packet)      
        if "nikto" in raw_data.lower(): # detects a Nikto scan
            count = count + 1
            print("ALERT #%i: Nikto scan is detected from %s to %s (%s)!" % (count, packet[IP].src, packet[IP].dst, packet.dport))
    
        if packet[TCP].dport == 445: # detects a SMB protocol
            count = count + 1
            print("ALERT #%i: SMB protocol is detected from %s to %s (%s)!" % (count, packet[IP].src, packet[IP].dst, packet.dport))
    
        if packet[TCP].dport == 21: # FTP username and password sniff
            payload = (packet[TCP].load.decode("ascii").strip())
            if "USER " in payload: # checks to see if there is a username in packet
                username = payload.split(" ")[1].strip()
                usernames.append(username)
            
            if "PASS " in payload: # checks to see if there is a password in packet
                password = payload.split(" ")[1].strip()
                passwords.append(password)
                
                if len(usernames) == len(passwords): # during the case when both username and password are retrieved, it will print out the credentials
                    count = count + 1
                    print("ALERT #%i: Usernames and passwords sent in-the-clear from %s to %s (%s) (username:%s, password:%s)" % (count, packet[IP].src, packet[IP].dst, socket.getservbyport(packet.dport), usernames[len(usernames) - 1], passwords[len(passwords) - 1]))
    
        if packet[TCP].dport == 80: # HTTP username and password sniff
            payload = (packet[TCP].load.decode("ascii").strip())
            if "Authorization:" in payload:
                count = count + 1
                credentials = HTTP_string_manipulate(payload)
                HTTP_credentials(credentials, packet[IP].src, packet[IP].dst, packet.dport)
        
        if packet[TCP].dport == 143: # IMAP username and password sniff
            payload = (packet[TCP].load.decode("ascii").strip())
            if "LOGIN" in payload:
                count = count + 1
                credentials = IMAP_string_manipulate(payload)
                IMAP_credentials(credentials, packet[IP].src, packet[IP].dst, packet.dport)  
          
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