# the_incident_alarm
A script that notifies the user of particular incidents from either a live stream of network packets or from a given PCAP file.

# What is this program capable of?
This program is capable of determining if the packets received consists of the following scans:
  * Null scans (found with TCP flag of "")
  * Fin scans (found with TCP flag of "F")
  * Xmas scans (found with TCP flag of "PFU")
  * Nikto scans (found within the payload when "nikto" appears)
  
Alongside determining scans, this program is capable of other following:
  * Retrieving usernames and password sent in-the-clear via:
      * HTTP Basic Authentication (found in port 80)
      * FTP (found in port 21)
      * IMAP (found in port 143)
  * Searching for Server Message Block (SMB) Protocol (found under port 443)
  
