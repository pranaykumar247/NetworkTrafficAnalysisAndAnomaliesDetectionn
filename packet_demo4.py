from scapy.all import *
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score, davies_bouldin_score, adjusted_rand_score, roc_auc_score, confusion_matrix
import matplotlib.pyplot as plt

# Function to parse packets from PCAP file
def parse_pcap(pcap_file):
    packets = rdpcap(pcap_file)  # Read packets from PCAP file
    source_ips = {}
    destination_ips = {}
    unique_source_ips = set()
    unique_destination_ips = set()
    source_ports = {}
    destination_ports = {}
    packet_sizes = []

    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    other_packets = 0
    total_bytes_transferred = 0

    for packet in packets:
        # Extract source IP, destination IP, source port, and destination port
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if src_ip in source_ips:
                source_ips[src_ip] += 1
            else:
                source_ips[src_ip] = 1
                unique_source_ips.add(src_ip)

            if dst_ip in destination_ips:
                destination_ips[dst_ip] += 1
            else:
                destination_ips[dst_ip] = 1
                unique_destination_ips.add(dst_ip)

        if TCP in packet:
            tcp_packets += 1
        elif UDP in packet:
            udp_packets += 1
        elif ICMP in packet:
            icmp_packets += 1
        else:
            other_packets += 1

        # Extract source port, destination port, and packet size
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = None
            dst_port = None

        if src_port:
            if src_port in source_ports:
                source_ports[src_port] += 1
            else:
                source_ports[src_port] = 1

        if dst_port:
            if dst_port in destination_ports:
                destination_ports[dst_port] += 1
            else:
                destination_ports[dst_port] = 1

        # Extract packet size
        packet_size = len(packet)
        packet_sizes.append(packet_size)
        total_bytes_transferred += packet_size

    # Calculate average packet size, min packet size, and max packet size
    num_packets = len(packet_sizes)
    if num_packets > 0:
        average_packet_size = sum(packet_sizes) / num_packets
        min_packet_size = min(packet_sizes)
        max_packet_size = max(packet_sizes)
    else:
        average_packet_size = 0
        min_packet_size = 0
        max_packet_size = 0

    return (source_ips, destination_ips, unique_source_ips, unique_destination_ips, source_ports, destination_ports, packet_sizes,
            tcp_packets, udp_packets, icmp_packets, other_packets,
            total_bytes_transferred, average_packet_size, min_packet_size, max_packet_size)

# Parse packets from PCAP file
(source_ips, destination_ips, unique_source_ips, unique_destination_ips, source_ports, destination_ports, packet_sizes,
 tcp_packets, udp_packets, icmp_packets, other_packets,
 total_bytes_transferred, average_packet_size, min_packet_size, max_packet_size) = parse_pcap("demo.pcap")

# Convert unique IPs to numerical representation for clustering
unique_source_ips_numeric = {ip: i for i, ip in enumerate(unique_source_ips)}
unique_destination_ips_numeric = {ip: i for i, ip in enumerate(unique_destination_ips)}

# Combine source and destination IPs into a single list for clustering
all_unique_ips = list(unique_source_ips_numeric.keys()) + list(unique_destination_ips_numeric.keys())


X = []
for ip in all_unique_ips:
    if ip in unique_source_ips_numeric and ip in unique_destination_ips_numeric:
        X.append([unique_source_ips_numeric[ip], unique_destination_ips_numeric[ip]])

# Convert X to numpy array
X = np.array(X)


######### 1st Algorithm ###########

# Apply K-means clustering
kmeans = KMeans(n_clusters=3, random_state=0).fit(X)

# Get cluster centers
cluster_centers = kmeans.cluster_centers_

# Print cluster centers
print("Cluster Centers:")
for center in cluster_centers:
    source_ip = all_unique_ips[int(center[0])]
    destination_ip = all_unique_ips[int(center[1])]
    print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")


kmeans.fit(X)
y_kmeans = kmeans.predict(X)


# Scatter plot
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=y_kmeans, alpha=0.5)
plt.title('Network Traffic Data for K-Means Clustering')
plt.xlabel('Packets Sent (from unique source IP)')
plt.ylabel('Packets Received (at unique destination IP)')
plt.legend(loc='upper right', fontsize='large')
plt.grid(True)
plt.show()




####### 2nd Algorithm #########


# Initialize Isolation Forest model
iso_forest = IsolationForest(contamination=0.1, random_state=42)

# Fit the model
iso_forest.fit(X)

# Predict outliers
outliers = iso_forest.predict(X)

# Visualize outliers
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=outliers, cmap='viridis', alpha=0.5)
plt.title('Isolation Forest Outlier Detection')
plt.xlabel('Packets Sent (from unique source IP)')
plt.ylabel('Packets Received (at unique destination IP)')
plt.legend(loc='upper right', fontsize='large')
plt.grid(True)
plt.colorbar(label='Outlier Score')
plt.show()


######### 3rd Algorithm ###########


# Initialize One-Class SVM model
svm = OneClassSVM(nu=0.1, kernel='rbf', gamma=0.1)

# Fit the model
svm.fit(X)

# Predict outliers
outliers_svm = svm.predict(X)

# Visualize outliers
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=outliers_svm, cmap='viridis', alpha=0.5)
plt.title('One-Class SVM Outlier Detection')
plt.xlabel('Packets Sent (from unique source IP)')
plt.ylabel('Packets Received (at unique destination IP)')
plt.legend(loc='upper right', fontsize='large')
plt.grid(True)
plt.colorbar(label='Outlier Score')
plt.show()


######### 4th Algorithm ###########

# Apply PCA
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)

# Visualize PCA-transformed data
plt.figure(figsize=(10, 6))
plt.scatter(X_pca[:, 0], X_pca[:, 1], alpha=0.5)
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.title('PCA')
plt.legend(fontsize='large')
plt.show()


######### 5th Algorithm ###########

# Create the Agglomerative Clustering model
agg_clustering = AgglomerativeClustering(n_clusters=3)

# Fit the model
agg_labels = agg_clustering.fit_predict(X)

# Plot Agglomerative Clustering clusters
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=agg_labels, cmap='viridis', alpha=0.5)
plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('Agglomerative Clustering')
plt.colorbar(label='Cluster Label')
plt.legend(fontsize='large')
plt.show()


######### 6th Algorithm ###########

# Create the DBSCAN model
dbscan = DBSCAN(eps=0.5, min_samples=5)

# Fit the model
dbscan.fit(X)

# Get cluster labels
dbscan_labels = dbscan.labels_

# Plot DBSCAN clusters
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=dbscan_labels, cmap='viridis', alpha=0.5)
plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('DBSCAN Clustering')
plt.colorbar(label='Cluster Label')
plt.legend(fontsize='large')
plt.show()




# K-Means Clustering
inertia = kmeans.inertia_
silhouette = silhouette_score(X, kmeans.labels_)
davies_bouldin = davies_bouldin_score(X, kmeans.labels_)

# Isolation Forest Outlier Detection
average_path_length = -iso_forest.decision_function(X)
percentage_outliers = np.mean(outliers == -1) * 100

# One-Class SVM Outlier Detection
outliers_svm = svm.predict(X)

# Principal Component Analysis (PCA)
variance_explained = np.sum(pca.explained_variance_ratio_)



print("Evaluation Metrics:")
print("K-Means Clustering:")
print(f"Inertia: {inertia}")
print(f"Silhouette Score: {silhouette}")
print(f"Davies-Bouldin Index: {davies_bouldin}")

print("\nIsolation Forest Outlier Detection:")
print(f"Average Path Length: {np.mean(average_path_length)}")
print(f"Percentage of Outliers Detected: {percentage_outliers}%")

print("\nOne-Class SVM Outlier Detection:")
# Since there are no true labels, you can't calculate TPR, FPR, or ROC AUC

print("\nPrincipal Component Analysis (PCA):")
print(f"Variance Explained: {variance_explained}")


############## Combined Algorithm ################
from collections import Counter

# Initialize lists to store predictions from each algorithm
predictions_kmeans = kmeans.predict(X)
predictions_iso_forest = iso_forest.predict(X)
predictions_svm = svm.predict(X)
predictions_agg = agg_clustering.fit_predict(X)
predictions_dbscan = dbscan.fit_predict(X)

# Initialize a list to store the combined predictions
combined_predictions = []

# Combine predictions using a voting ensemble
for i in range(len(X)):
    # Count the votes from each algorithm
    votes = Counter([predictions_kmeans[i], predictions_iso_forest[i], predictions_svm[i], predictions_agg[i], predictions_dbscan[i]])
    
    # Get the most common prediction (majority vote)
    combined_prediction = votes.most_common(1)[0][0]
    
    # Add the combined prediction to the list
    combined_predictions.append(combined_prediction)

# Convert the list of combined predictions to a numpy array
combined_predictions = np.array(combined_predictions)

# Plot the combined predictions
plt.figure(figsize=(10, 6))
plt.scatter(X[:, 0], X[:, 1], c=combined_predictions, cmap='viridis', alpha=0.5)
plt.xlabel('Packets Sent (from unique source IP)')
plt.ylabel('Packets Received (at unique destination IP)')
plt.title('Combined Anomaly Detection Results')
plt.colorbar(label='Cluster Label')
plt.grid(True)
plt.show()




