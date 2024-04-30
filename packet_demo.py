import pyshark

# Path to the exported packet file (e.g., pcap file)
pcap_file = 'demo.pcap'

# Open the pcap file for reading
capture = pyshark.FileCapture(pcap_file)

# Iterate over each packet and process them
for packet in capture:
    # Process packet data here
    print(packet)
    
capture.close()
