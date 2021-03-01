# the_incident_alarm
A script that notifies the user of particular incidents from either a live 
stream of network packets or from a given PCAP file.

# What is this program capable of?
This program is capable of determining if the packets received consists of the following scans:
  * Null scans (found with TCP flag of "")
  * Fin scans (found with TCP flag of "F")
  * Xmas scans (found with TCP flag of "PFU")
  * Nikto scans (found within the payload when "nikto" appears)
  
