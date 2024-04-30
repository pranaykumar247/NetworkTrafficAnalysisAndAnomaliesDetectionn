import pyshark
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import OneHotEncoder
from scipy.sparse import csr_matrix

# Path to the exported packet file 
pcap_file = 'demo.pcap'

# Open the pcap file for reading
capture = pyshark.FileCapture(pcap_file)

# Initialize lists to store packet information
data = []

# Initialize sets to store unique IPs and common IPs
unique_source_ips = set()
unique_destination_ips = set()
common_ips = set()

# Iterate over each packet and extract relevant information
for packet in capture:
    if 'IP' in packet:
        ip = packet['IP']
        src_ip = ip.src
        dst_ip = ip.dst
        
        unique_source_ips.add(src_ip)
        unique_destination_ips.add(dst_ip)
        
        # Check if IP is common (present in both source and destination)
        if src_ip in unique_destination_ips:
            common_ips.add(src_ip)
        if dst_ip in unique_source_ips:
            common_ips.add(dst_ip)
        
        if 'TCP' in packet:
            src_port = packet['TCP'].srcport
            dst_port = packet['TCP'].dstport
            # Example: check if port is closed or open
            if packet['TCP'].flags == '0x0002':  # SYN flag set (open port)
                port_status = 'open'
            else:
                port_status = 'closed'
        elif 'UDP' in packet:
            src_port = packet['UDP'].srcport
            dst_port = packet['UDP'].dstport
            port_status = 'unknown'  # Cannot determine port status for UDP
        else:
            src_port = None
            dst_port = None
            port_status = 'unknown'
        
        data.append([src_ip, dst_ip, src_port, dst_port, port_status])

# Close the capture file
capture.close()

# Create a DataFrame from the extracted data
columns = ['SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'PortStatus']
df = pd.DataFrame(data, columns=columns)

# Drop rows with missing values (None) in 'SourcePort' column
df = df.dropna(subset=['SourcePort'])

# Perform one-hot encoding for categorical features
encoder = OneHotEncoder()
encoded_features = encoder.fit_transform(df[['SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'PortStatus']])

# Convert encoded features to CSR format
encoded_features_csr = csr_matrix(encoded_features)

# Visualize network flow by source IP
plt.figure(figsize=(12, 6))
df['SourceIP'].value_counts().plot(kind='bar', color='skyblue')
plt.title('Network Traffic by Source IP')
plt.xlabel('Source IP')
plt.ylabel('Packet Count')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Create bar plot for comparing unique IPs and common IPs
unique_source_count = len(unique_source_ips)
unique_destination_count = len(unique_destination_ips)
common_count = len(common_ips)

plt.figure(figsize=(10, 6))
plt.bar(['Unique Source IPs', 'Unique Destination IPs', 'Common IPs'], [unique_source_count, unique_destination_count, common_count], color=['skyblue', 'lightgreen', 'salmon'])
plt.title('Comparison of Unique IPs and Common IPs')
plt.xlabel('IP Type')
plt.ylabel('Count')
plt.show()

# Separate closed, open, and unknown ports for scatter plot
closed_ports = df[df['PortStatus'] == 'closed']
open_ports = df[df['PortStatus'] == 'open']
unknown_ports = df[df['PortStatus'] == 'unknown']

# Scatter plot for comparing closed, open, and unknown ports based on the IPs
plt.figure(figsize=(11, 11))
plt.scatter(closed_ports['SourceIP'], closed_ports['SourcePort'], c='red', label='Closed', alpha=0.5)
plt.scatter(open_ports['SourceIP'], open_ports['SourcePort'], c='green', label='Open', alpha=0.5)
plt.scatter(unknown_ports['SourceIP'], unknown_ports['SourcePort'], c='blue', label='Unknown', alpha=0.5)
plt.title('Scatter Plot for Port Status based on Source IPs')
plt.xlabel('Source IP')
plt.ylabel('Source Port')
plt.legend(loc='upper right')  # Adjusted legend location
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
