import sys
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QAction, QMessageBox, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
import pyshark
import joblib
import pandas as pd
from collections import deque


class DDoSDetector(QThread):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.model = joblib.load('ddos_rf_model_augmented.pkl')
        self.packet_counts = deque()
        self.byte_counts = deque()
        self.window_size = 1  # seconds
        self.monitoring = False

    def run(self):
        self.monitoring = True
        capture = pyshark.LiveCapture(interface='Wi-Fi')  # Adjust interface
        for packet in capture.sniff_continuously():
            if not self.monitoring:
                break
            self.process_packet(packet)

    def process_packet(self, packet):
        try:
            packet_length = int(packet.length)
            current_time = time.time()
            self.packet_counts.append((current_time, 1))
            self.byte_counts.append((current_time, packet_length))

            # Remove old packets
            while self.packet_counts and current_time - self.packet_counts[0][0] > self.window_size:
                self.packet_counts.popleft()
            while self.byte_counts and current_time - self.byte_counts[0][0] > self.window_size:
                self.byte_counts.popleft()

            packet_count = sum(count for _, count in self.packet_counts)
            byte_count = sum(size for _, size in self.byte_counts)

            packet_count_per_sec = packet_count / self.window_size
            byte_count_per_sec = byte_count / self.window_size

            avg_packet_size = byte_count / packet_count if packet_count != 0 else 0

            features = pd.DataFrame([[packet_count, packet_count_per_sec, byte_count, byte_count_per_sec, avg_packet_size]],
                                    columns=['packet_count', 'packet_count_per_second', 'byte_count', 'byte_count_per_second', 'avg_packet_size'])

            if packet_count > 50000:
                self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
            else:
                prediction = self.model.predict(features)
                traffic_type = prediction[0]

                if traffic_type == 1:
                    self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
                else:
                    self.log_signal.emit("✅ Normal Traffic")

        except AttributeError:
            pass  # Ignore packets without length attribute

    def stop(self):
        self.monitoring = False

    def inject_ddos_sample(self):
        packet_count = 100000
        packet_count_per_sec = 5000
        byte_count = 10000000
        byte_count_per_sec = 800000

        self.log_signal.emit("\n🚨 Injecting synthetic DDoS sample for testing...")
        self.process_synthetic_traffic(packet_count, packet_count_per_sec, byte_count, byte_count_per_sec)

    def process_synthetic_traffic(self, packet_count, packet_count_per_sec, byte_count, byte_count_per_sec):
        avg_packet_size = byte_count / packet_count if packet_count != 0 else 0
        features = pd.DataFrame([[packet_count, packet_count_per_sec, byte_count, byte_count_per_sec, avg_packet_size]],
                                columns=['packet_count', 'packet_count_per_second', 'byte_count', 'byte_count_per_second', 'avg_packet_size'])

        if packet_count > 50000:
            self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
        else:
            prediction = self.model.predict(features)
            traffic_type = prediction[0]

            if traffic_type == 1:
                self.alert_signal.emit("🚨 DDoS Attack Detected! 🚨")
            else:
                self.log_signal.emit("✅ Normal Traffic")


class AegisApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.detector = DDoSDetector()
        self.detector.log_signal.connect(self.update_log)
        self.detector.alert_signal.connect(self.show_alert)

    def initUI(self):
        self.setWindowTitle('Aegis - DDoS Detection System')

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)

        self.start_button = QPushButton('Start Monitoring')
        self.start_button.clicked.connect(self.start_monitoring)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Monitoring')
        self.stop_button.clicked.connect(self.stop_monitoring)
        layout.addWidget(self.stop_button)

        self.inject_button = QPushButton('Inject Synthetic DDoS')
        self.inject_button.clicked.connect(self.inject_ddos)
        layout.addWidget(self.inject_button)

        menubar = self.menuBar()
        about_menu = menubar.addMenu('About')
        about_action = QAction('About Aegis', self)
        about_action.triggered.connect(self.show_about)
        about_menu.addAction(about_action)

    def start_monitoring(self):
        self.log_display.append("🚦 Monitoring started...\n")
        self.detector.start()

    def stop_monitoring(self):
        self.detector.stop()
        self.log_display.append("🛑 Monitoring stopped by user.\n")

    def inject_ddos(self):
        self.detector.inject_ddos_sample()

    def update_log(self, message):
        self.log_display.append(message)

    def show_alert(self, message):
        QMessageBox.warning(self, "Alert", message)

    def show_about(self):
        QMessageBox.information(self, "About Aegis", "Aegis DDoS Detection System\nBuilt with PyQt5.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AegisApp()
    window.show()
    sys.exit(app.exec_())
