import socket

UDP_IP = "127.0.0.1"  # Use localhost
UDP_PORT = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print("Listening for packet data...")
while True:
    data, addr = sock.recvfrom(65536)  # Adjust buffer size as needed
    print(data.decode('utf-8'))  # Example: Print the packet data
