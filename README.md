# the_incident_alarm
A script that notifies the user of particular incidents from either a live stream of network packets or from a given PCAP file.

# Dependencies/libraries used
Four dependencies/libraries were used:
  * scapy
      * provided documentation to sniff through packets for specific incidents
  * base64
      * assists in decoding base64 byte strings, particularly for credentials encoded in base64
  * socket
      * converts TCP protocols like HTTP, FTP, and IMAP from their numerical port values to their string names
  * argparse
      * enables parsing arguments passed through console when running program.

# What is this program capable of?
This program is capable of determining if the packets received from either live stream interface or PCAP files consists of the following scans:
  * Null scans (found with TCP flag of "")
  * Fin scans (found with TCP flag of "F")
  * Xmas scans (found with TCP flag of "PFU")
  * Nikto scans (found within the payload when "nikto" appears)
  
Alongside determining scans, this program is capable of other following:
  * Retrieving usernames and password sent in-the-clear via:
      * HTTP Basic Authentication (found in port 80)
      * FTP (found in port 21)
      * IMAP (found in port 143)
  * Searching for Server Message Block (SMB) Protocol (found in port 445)
