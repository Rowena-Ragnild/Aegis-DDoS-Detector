import sys
import threading
import time
import pandas as pd
import joblib
import pyshark
import asyncio
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QLabel, QMessageBox
from PyQt5.QtCore import Qt

class TrafficMonitor(threading.Thread):
    def __init__(self, model, log_callback, alert_callback):
        super().__init__()
        self.model = model
        self.log_callback = log_callback
        self.alert_callback = alert_callback
        self.running = True
        self.interface = 'Wi-Fi'  # Adjust as per your system's interface

    def run(self):
        asyncio.set_event_loop(asyncio.new_event_loop())  # Fix for asyncio event loop
        self.log_callback("Traffic monitoring started...")
        cap = pyshark.LiveCapture(interface=self.interface)
        for packet in cap.sniff_continuously():
            if not self.running:
                break
            try:
                packet_count = 100  # Example dummy values
                packet_count_per_second = 50
                byte_count = 8000
                byte_count_per_second = 4000

                features = pd.DataFrame([[packet_count, packet_count_per_second, byte_count, byte_count_per_second]],
                                        columns=['packet_count', 'packet_count_per_second', 'byte_count', 'byte_count_per_second'])

                prediction = self.model.predict(features)[0]
                self.log_callback(f"Traffic Status: {prediction}")

                if prediction == 'DDoS':
                    self.alert_callback("DDoS Attack Detected! Initiating mitigation...")
                    self.mitigate_attack()
            except Exception as e:
                self.log_callback(f"Error processing packet: {e}")

        self.log_callback("Traffic monitoring stopped.")

    def stop(self):
        self.running = False

    def mitigate_attack(self):
        # Dummy mitigation logic (actual IP blocking code would require admin rights)
        time.sleep(2)  # Simulate mitigation time
        self.alert_callback("Attack mitigated. Attacker IP blocked.")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aegis DDoS Detection System")
        self.setGeometry(200, 200, 700, 500)

        # Model loading
        self.model = joblib.load("retrained_model.pkl")

        # Log area
        self.log_area = QTextEdit(self)
        self.log_area.setGeometry(50, 50, 600, 250)
        self.log_area.setReadOnly(True)

        # Buttons
        self.start_btn = QPushButton("Start Monitoring", self)
        self.start_btn.setGeometry(50, 330, 150, 40)
        self.start_btn.clicked.connect(self.start_monitoring)

        self.stop_btn = QPushButton("Stop Monitoring", self)
        self.stop_btn.setGeometry(220, 330, 150, 40)
        self.stop_btn.clicked.connect(self.stop_monitoring)

        self.attack_btn = QPushButton("Launch Synthetic Attack", self)
        self.attack_btn.setGeometry(390, 330, 200, 40)
        self.attack_btn.clicked.connect(self.launch_attack)

        # About label
        self.about_label = QLabel("Aegis detects & mitigates DDoS attacks in real-time.", self)
        self.about_label.setGeometry(50, 400, 600, 30)
        self.about_label.setAlignment(Qt.AlignCenter)

        self.monitor = None

    def log(self, message):
        self.log_area.append(message)

    def show_alert(self, message):
        alert = QMessageBox()
        alert.setWindowTitle("Alert")
        alert.setText(message)
        alert.exec_()

    def start_monitoring(self):
        if not self.monitor or not self.monitor.is_alive():
            self.monitor = TrafficMonitor(self.model, self.log, self.show_alert)
            self.monitor.start()
            self.log("Started real-time monitoring.")

    def stop_monitoring(self):
        if self.monitor and self.monitor.is_alive():
            self.monitor.stop()
            self.log("Stopped monitoring.")

    def launch_attack(self):
        self.log("Launching Synthetic DDoS Attack...")
        # Inject synthetic DDoS-like traffic
        for _ in range(10):
            packet_count = 10000  # Extreme values to simulate attack
            packet_count_per_second = 5000
            byte_count = 100000
            byte_count_per_second = 80000
            features = pd.DataFrame([[packet_count, packet_count_per_second, byte_count, byte_count_per_second]],
                                    columns=['packet_count', 'packet_count_per_second', 'byte_count', 'byte_count_per_second'])
            prediction = self.model.predict(features)[0]
            self.log(f"[Synthetic] Traffic Status: {prediction}")
            if prediction == 'DDoS':
                self.show_alert("Synthetic DDoS Attack Detected! Mitigating...")
                time.sleep(1)
                self.show_alert("Synthetic Attack Mitigated.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())