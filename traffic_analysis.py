from sklearn.ensemble import IsolationForest
import numpy as np

traffic_data = []

def analyze_traffic(packet):
    """Collects traffic data for anomaly detection."""
    try:
        traffic_data.append([int(packet.length), int(packet.ip.ttl)])
        if len(traffic_data) > 100:
            detect_anomalies()
    except AttributeError:
        pass

def detect_anomalies():
    """Runs anomaly detection on traffic data."""
    model = IsolationForest(contamination=0.1)
    predictions = model.fit_predict(np.array(traffic_data))
    for i, prediction in enumerate(predictions):
        if prediction == -1:
            print(f"Anomaly detected in packet {i}")
