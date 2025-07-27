import sys
import pickle
import pandas as pd
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.QtWidgets import QPushButton, QTextEdit
from scapy.all import sniff
import subprocess

class DDoSDetector(QThread):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.model = None
        self.load_model()

    def load_model(self):
        try:
            # Load the model from the pickle file
            with open("ddos_rf_model_augmented.pkl", "rb") as model_file:
                self.model = pickle.load(model_file)
            self.log_signal.emit("Model loaded successfully")
        except Exception as e:
            self.log_signal.emit(f"Error loading model: {e}")

    def inject_synthetic_ddos(self):
        # Inject synthetic DDoS traffic for testing
        self.log_signal.emit("🚨 Injecting synthetic DDoS traffic...")
        # Define extreme values for testing
        packet_count = 1000000
        packet_count_per_sec = 50000
        byte_count = 100000000
        byte_count_per_sec = 8000000

        # Calculate avg_packet_size (feature missing warning)
        avg_packet_size = byte_count / packet_count if packet_count != 0 else 0

        # Prepare features as DataFrame
        features = pd.DataFrame([{
            'packet_count': packet_count,
            'packet_count_per_second': packet_count_per_sec,
            'byte_count': byte_count,
            'byte_count_per_second': byte_count_per_sec,
            'avg_packet_size': avg_packet_size  # Add missing feature
        }])

        # Try predicting DDoS traffic
        try:
            prediction = self.model.predict(features)
            traffic_type = prediction[0]

            if traffic_type == 1:  # Assuming 1 represents DDoS
                self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
                self.mitigate_attack("192.168.1.100")  # Example IP for mitigation (change this to the real attacking IP)
            else:
                self.log_signal.emit("✅ Normal Traffic")
        except Exception as e:
            self.log_signal.emit(f"Error during prediction: {e}")

    def mitigate_attack(self, ip_address):
        """ Mitigate DDoS attack by blocking the IP address """
        self.log_signal.emit(f"⚠️ Mitigating DDoS attack from IP: {ip_address}")
        
        try:
            # Block the attacking IP using netsh (Windows firewall)
            command = f'netsh advfirewall firewall add rule name="Block DDoS IP" dir=in action=block remoteip={ip_address}'
            subprocess.run(command, shell=True)
            self.log_signal.emit(f"✅ IP {ip_address} has been blocked.")
        except Exception as e:
            self.log_signal.emit(f"Error during mitigation: {e}")

    def start_monitoring(self):
        # Start sniffing packets to monitor traffic
        self.log_signal.emit("🚦 Monitoring started...")
        sniff(prn=self.process_packet, store=0, count=0)

    def process_packet(self, packet):
        # Example of how to process packet and extract features
        packet_count = len(packet)
        packet_count_per_sec = 0  # Placeholder (You can calculate this with time-based logic)
        byte_count = len(packet)
        byte_count_per_sec = 0  # Placeholder (You can calculate this with time-based logic)

        # Call prediction
        self.predict_traffic(packet_count, packet_count_per_sec, byte_count, byte_count_per_sec)

    def predict_traffic(self, packet_count, packet_count_per_sec, byte_count, byte_count_per_sec):
        if not self.model:
            self.log_signal.emit("Model is not loaded!")
            return

        # Calculate avg_packet_size if required
        avg_packet_size = byte_count / packet_count if packet_count != 0 else 0

        # Prepare features as DataFrame (including avg_packet_size)
        features = pd.DataFrame([{
            'packet_count': packet_count,
            'packet_count_per_second': packet_count_per_sec,
            'byte_count': byte_count,
            'byte_count_per_second': byte_count_per_sec,
            'avg_packet_size': avg_packet_size  # Add the missing feature
        }])

        # Make prediction using the model
        try:
            prediction = self.model.predict(features)
            traffic_type = prediction[0]

            if traffic_type == 1:  # Assuming 1 represents DDoS
                self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
                # Implement mitigation logic here (block IP, etc.)
                self.mitigate_attack("192.168.1.100")  # Example IP, replace with dynamic IP detection logic
            else:
                self.log_signal.emit("✅ Normal Traffic")
        except Exception as e:
            self.log_signal.emit(f"Error during prediction: {e}")


class AegisApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.detector_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Aegis DDoS Detector")
        self.setGeometry(100, 100, 600, 400)

        self.start_btn = QPushButton("Start Monitoring", self)
        self.start_btn.clicked.connect(self.start_monitoring)
        self.start_btn.setGeometry(50, 100, 200, 50)

        self.stop_btn = QPushButton("Stop Monitoring", self)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setGeometry(50, 200, 200, 50)

        self.inject_ddos_btn = QPushButton("Inject DDoS Traffic", self)
        self.inject_ddos_btn.clicked.connect(self.inject_synthetic_ddos)
        self.inject_ddos_btn.setGeometry(300, 100, 200, 50)

        self.log_display = QTextEdit(self)
        self.log_display.setGeometry(50, 300, 500, 100)

    def start_monitoring(self):
        # Start the monitoring in a separate thread
        self.detector_thread = DDoSDetector()
        self.detector_thread.log_signal.connect(self.append_log)
        self.detector_thread.alert_signal.connect(self.show_alert)
        self.detector_thread.start()
        self.detector_thread.start_monitoring()

    def stop_monitoring(self):
        if self.detector_thread:
            self.detector_thread.terminate()
            self.append_log("🛑 Monitoring stopped.")

    def inject_synthetic_ddos(self):
        if self.detector_thread:
            self.detector_thread.inject_synthetic_ddos()

    def append_log(self, message):
        self.log_display.append(message)

    def show_alert(self, message):
        QMessageBox.warning(self, "Alert", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AegisApp()
    window.show()
    sys.exit(app.exec_())
