import pyshark
import socket
import nmap

# Path to the exported packet file 
pcap_file = 'demo.pcap'

# Open the pcap file for reading
capture = pyshark.FileCapture(pcap_file)

# Initialize counters for statistics
total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0
other_packets = 0

# Initialize dictionaries to store additional information
source_ips = {}
destination_ips = {}
source_ports = {}
destination_ports = {}
open_ports = set()

# Iterate over each packet and process them
for packet in capture:
    total_packets += 1
    
    # Extract protocol type (e.g., TCP, UDP, ICMP)
    if 'IP' in packet:
        ip = packet['IP']
        protocol = ip.proto
        src_ip = ip.src
        dst_ip = ip.dst
        
        # Count packets for each protocol type
        if protocol == '6':  # TCP protocol
            tcp_packets += 1
        elif protocol == '17':  # UDP protocol
            udp_packets += 1
        elif protocol == '1':  # ICMP protocol
            icmp_packets += 1
        else:
            other_packets += 1
        
        # Track source and destination IPs
        if src_ip not in source_ips:
            source_ips[src_ip] = 1
        else:
            source_ips[src_ip] += 1
        
        if dst_ip not in destination_ips:
            destination_ips[dst_ip] = 1
        else:
            destination_ips[dst_ip] += 1
        
        # Extract source and destination ports (if applicable)
        if 'TCP' in packet:
            src_port = packet['TCP'].srcport
            dst_port = packet['TCP'].dstport
        elif 'UDP' in packet:
            src_port = packet['UDP'].srcport
            dst_port = packet['UDP'].dstport
        else:
            src_port = None
            dst_port = None
        
        # Track source and destination ports
        if src_port:
            if src_port not in source_ports:
                source_ports[src_port] = 1
            else:
                source_ports[src_port] += 1
            open_ports.add(src_port)
        
        if dst_port:
            if dst_port not in destination_ports:
                destination_ports[dst_port] = 1
            else:
                destination_ports[dst_port] += 1
            open_ports.add(dst_port)

# Print statistics
print("Total packets:", total_packets)
print("TCP packets:", tcp_packets)
print("UDP packets:", udp_packets)
print("ICMP packets:", icmp_packets)
print("Other packets:", other_packets)

# Print detailed information
print("\nSource IPs:")
for ip, count in source_ips.items():
    print(ip, "-", count, "packets")

print("\nDestination IPs:")
for ip, count in destination_ips.items():
    print(ip, "-", count, "packets")

print("\nSource Ports:")
for port, count in source_ports.items():
    print(port, "-", count, "packets")

print("\nDestination Ports:")
for port, count in destination_ports.items():
    print(port, "-", count, "packets")

print("\nOpen Ports:")
for port in open_ports:
    print(port)

# Close the capture file
capture.close()

# Perform OS detection using nmap
nm = nmap.PortScanner()
for ip in destination_ips.keys():
    ip_address = str(ip)  # Convert the IP address object to a string
    nm.scan(ip_address, arguments='-O')
    print("\nOS detection for", ip_address, ":")
    if ip_address in nm.all_hosts():
        if 'osclass' in nm[ip_address]:
            print(nm[ip_address]['osclass'])
        else:
            print("No OS information available")
    else:
        print("No scan result available for", ip_address)

