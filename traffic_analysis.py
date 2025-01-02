from sklearn.ensemble import IsolationForest
import numpy as np
from logger import log_event, log_anomaly
import time

# Store traffic data for analysis
traffic_data = []

# Define a time window for monitoring anomalies (in seconds)
monitoring_window = 60
last_anomaly_check = time.time()

def analyze_traffic(packet):
    """Collects traffic data for anomaly detection."""
    try:
        # Collecting packet length and TTL as traffic features for anomaly detection
        packet_features = [int(packet.length), int(packet.ip.ttl)]
        traffic_data.append(packet_features)

        # If we have more than 100 packets, run anomaly detection
        if len(traffic_data) > 100:
            detect_anomalies()

    except AttributeError:
        # Handle packets that do not have IP layer information
        pass

def detect_anomalies():
    """Runs anomaly detection on traffic data."""
    global last_anomaly_check

    # Run anomaly detection if enough time has passed (to prevent constant detection checks)
    current_time = time.time()
    if current_time - last_anomaly_check < monitoring_window:
        return  # Only run detection once every 60 seconds

    if len(traffic_data) < 100:
        return  # We need at least 100 packets to start detecting anomalies

    try:
        model = IsolationForest(contamination=0.1)  # Contamination set to 10% for the anomaly ratio
        predictions = model.fit_predict(np.array(traffic_data))

        for i, prediction in enumerate(predictions):
            if prediction == -1:  # -1 indicates an anomaly
                packet = traffic_data[i]
                log_anomaly(packet, f"Anomaly detected in packet {i} (Length: {packet[0]} bytes, TTL: {packet[1]})")

        last_anomaly_check = current_time
        traffic_data.clear()  # Clear the traffic data after detection

    except Exception as e:
        log_event("Error", f"Anomaly detection error: {e}")

