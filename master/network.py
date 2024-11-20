import time
import logging
import threading
import joblib
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import numpy as np

# Constants
TIME_WINDOW = 3  # Time window in seconds to measure traffic
FEATURES = ['incoming_count', 'outgoing_count', 'incoming_outgoing_ratio']  # Features for ML model

# Packet counts
incoming_packet_counts = defaultdict(int)
outgoing_packet_counts = defaultdict(int)

# Load pre-trained ML model
MODEL_PATH = "dos_ddos_model.pkl"
model = joblib.load(MODEL_PATH)

# Set up logging
logging.basicConfig(filename='logs/dos_attack_ml_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

def is_ongoing_connection_packet(tcp_flags):
    """
    Determine if the TCP packet is part of an ongoing connection.
    """
    return 'S' not in tcp_flags and tcp_flags != 'A'

def analyze_packet(packet):
    """
    Analyze incoming packets and update counts.
    """
    if IP in packet and TCP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        tcp_layer = packet[TCP]

        # Check if it's an incoming packet directed to the server
        if destination_ip == "172.20.0.2":  # Replace with your server IP
            if tcp_layer.flags == 'S':  # SYN packet
                incoming_packet_counts[source_ip] += 1
        else:
            # Outgoing packet
            if is_ongoing_connection_packet(tcp_layer.flags):
                outgoing_packet_counts[destination_ip] += 1

def extract_features():
    """
    Extract features for the ML model from the packet counts.
    """
    features = []
    ips = list(incoming_packet_counts.keys() | outgoing_packet_counts.keys())
    for ip in ips:
        incoming_count = incoming_packet_counts[ip]
        outgoing_count = outgoing_packet_counts[ip]
        incoming_outgoing_ratio = (
            incoming_count / outgoing_count if outgoing_count > 0 else 0
        )
        features.append([incoming_count, outgoing_count, incoming_outgoing_ratio])
    return ips, features

def classify_traffic():
    """
    Classify traffic using the ML model and log results.
    """
    ips, features = extract_features()
    if features:
        predictions = model.predict(features)
        for ip, prediction in zip(ips, predictions):
            if prediction == 1:  # Assuming 1 means a DoS/DDoS attack
                alert_message = f"[ALERT] DoS/DDoS attack detected from IP: {ip}"
                logging.info(alert_message)
                print(alert_message)
            else:
                normal_message = f"Normal traffic from IP: {ip}"
                logging.info(normal_message)
                print(normal_message)

def monitor_traffic():
    """
    Monitor traffic and periodically classify it.
    """
    while True:
        time.sleep(TIME_WINDOW)
        classify_traffic()
        incoming_packet_counts.clear()
        outgoing_packet_counts.clear()
        logging.info("Traffic counters reset for the next time window.")

if __name__ == "__main__":
    startup_message = "Starting network analysis with ML integration..."
    print(startup_message)
    logging.info(startup_message)

    # Start a separate thread to sniff packets
    sniff_thread = threading.Thread(target=lambda: sniff(prn=analyze_packet, filter="tcp", store=0, iface="eth0", count=0))
    sniff_thread.start()
    logging.info("Packet sniffing started...")

    # Run traffic monitoring and classification
    monitor_traffic()
