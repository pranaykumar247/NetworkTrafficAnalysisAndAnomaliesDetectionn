import pyshark

# Define the network interface to capture packets from
interface = 'Wi-Fi'

# Start a live packet capture on the specified interface
capture = pyshark.LiveCapture(interface=interface)

# Initialize a counter to track the number of captured packets
packet_count = 0

# Iterate over each captured packet and process them in real-time
for packet in capture.sniff_continuously():
    # Print the packet information
    print(packet)
    
    # Increment the packet count
    packet_count += 1

    
    if packet_count >= 100:
        break

# Close the capture once done
capture.close()
