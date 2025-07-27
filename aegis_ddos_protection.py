import sys
import os
import pandas as pd
from scapy.all import sniff
from sklearn.ensemble import RandomForestClassifier
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QPushButton, QLabel
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import joblib
import time

# DDoS Detection Model
class DDoSDetector:
    def __init__(self):
        self.model = self.load_model()

    def load_model(self):
        model_path = 'ddos_rf_model_augmented.pkl'  # Path to your trained model
        try:
            model = joblib.load(model_path)
            print(f"Model loaded successfully from {model_path}")
        except FileNotFoundError:
            print(f"Model file not found at {model_path}")
            model = None
        return model

    def predict(self, features):
        if self.model:
            df = pd.DataFrame([features])
            prediction = self.model.predict(df)
            return prediction[0]
        else:
            print("No model loaded. Cannot predict.")
            return None

# Network Monitor
class NetworkMonitor(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, detector):
        super().__init__()
        self.detector = detector
        self.monitoring = False

        # For calculating features per second
        self.packet_count = 0
        self.byte_count = 0
        self.start_time = time.time()

    def run(self):
        sniff(prn=self.process_packet, store=0, stop_filter=self.stop_sniffing)

    def process_packet(self, packet):
        if not self.monitoring:
            return

        # Update counters
        self.packet_count += 1
        self.byte_count += len(packet)

        current_time = time.time()
        elapsed_time = current_time - self.start_time

        # Calculate features every second
        if elapsed_time >= 1:
            packet_count_per_second = self.packet_count
            byte_count_per_second = self.byte_count
            avg_packet_size = self.byte_count / self.packet_count if self.packet_count != 0 else 0

            features = {
                'packet_count': self.packet_count,
                'packet_count_per_second': packet_count_per_second,
                'byte_count': self.byte_count,
                'byte_count_per_second': byte_count_per_second,
                'avg_packet_size': avg_packet_size
            }

            prediction = self.detector.predict(features)

            if prediction == 'DDoS':
                try:
                    src_ip = packet[0][1].src
                    self.update_signal.emit(f"DDoS detected from {src_ip}. Blocking IP.")
                    self.block_ip(src_ip)
                except:
                    self.update_signal.emit(f"DDoS detected. Blocking traffic.")

            else:
                self.update_signal.emit("Normal traffic detected.")

            # Reset counters for next second
            self.packet_count = 0
            self.byte_count = 0
            self.start_time = time.time()

    def block_ip(self, ip_address):
        command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
        os.system(command)

    def stop_sniffing(self, packet):
        return not self.monitoring

    def start_monitoring(self):
        self.monitoring = True
        self.start()

    def stop_monitoring(self):
        self.monitoring = False

# PyQt5 GUI
class AegisApp(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Aegis - Real-time DDoS Detection')
        self.setGeometry(100, 100, 400, 200)
        self.detector = DDoSDetector()
        self.monitor = NetworkMonitor(self.detector)
        self.monitor.update_signal.connect(self.update_status)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.status_label = QLabel('Status: Idle', self)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.start_button = QPushButton('Start Monitoring', self)
        self.start_button.clicked.connect(self.start_monitoring)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Monitoring', self)
        self.stop_button.clicked.connect(self.stop_monitoring)
        layout.addWidget(self.stop_button)

        self.setLayout(layout)

    def start_monitoring(self):
        self.status_label.setText('Status: Monitoring...')
        self.monitor.start_monitoring()

    def stop_monitoring(self):
        self.monitor.stop_monitoring()
        self.status_label.setText('Status: Stopped')

    def update_status(self, message):
        self.status_label.setText(f'Status: {message}')

# Main
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AegisApp()
    window.show()
    sys.exit(app.exec_())
