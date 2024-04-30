import pyshark

# Path to the exported packet file (e.g., pcap file)
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
        
        if dst_port:
            if dst_port not in destination_ports:
                destination_ports[dst_port] = 1
            else:
                destination_ports[dst_port] += 1

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

# Close the capture file
capture.close()

# Compare Destination IPs with Source IPs
common_ips = set(source_ips.keys()) & set(destination_ips.keys())
unique_source_ips = set(source_ips.keys()) - common_ips
unique_destination_ips = set(destination_ips.keys()) - common_ips

# Print Common IPs
print("\nCommon IPs (Both Source and Destination):")
for ip in common_ips:
    print(ip, "- Packets sent and received:", source_ips[ip])

# Print Unique Source IPs
print("\nUnique Source IPs:")
for ip in unique_source_ips:
    print(ip, "- Packets sent:", source_ips[ip])

# Print Unique Destination IPs
print("\nUnique Destination IPs:")
for ip in unique_destination_ips:
    print(ip, "- Packets received:", destination_ips[ip])
    
    
    
    
############################# Process of anomalies detection starts here #################################

from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report

# Extract features and labels
X = []
y = []


# Example feature extraction
for ip in source_ips.keys():
    X.append([source_ips[ip], destination_ips.get(ip, 0)])  # Example features
    if ip in common_ips:
        y.append(0)  # Normal traffic
    else:
        y.append(1)  # Anomalous traffic
        
# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Support Vector Machine (SVM)
svm_classifier = SVC(kernel='linear', C=0.1, random_state=42)
svm_classifier.fit(X_train, y_train)

# Predictions
svm_predictions = svm_classifier.predict(X_test)

# Evaluate SVM
svm_accuracy = accuracy_score(y_test, svm_predictions)
svm_report = classification_report(y_test, svm_predictions)

print("SVM Accuracy:", svm_accuracy)
print("SVM Report:")
print(svm_report)

# Decision Tree
dt_classifier = DecisionTreeClassifier(max_depth = 3, random_state=42)
dt_classifier.fit(X_train, y_train)

# Predictions
dt_predictions = dt_classifier.predict(X_test)

# Evaluate Decision Tree
dt_accuracy = accuracy_score(y_test, dt_predictions)
dt_report = classification_report(y_test, dt_predictions)

print("\nDecision Tree Accuracy:", dt_accuracy)
print("Decision Tree Report:")
print(dt_report)
        
        