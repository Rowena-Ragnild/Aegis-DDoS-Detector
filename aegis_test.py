import sys
import asyncio
import threading
import joblib
import pandas as pd
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QTextEdit, QMessageBox
from PyQt5.QtCore import pyqtSignal, QObject
import pyshark
import socket
import subprocess
from scapy.all import IP, UDP, Raw, send

class Communicate(QObject):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

class DDoSDetector(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.monitoring = False
        self.comm = Communicate()
        self.comm.log_signal.connect(self.updateLog)
        self.comm.status_signal.connect(self.updateStatus)
        self.model = joblib.load('retrained_model.pkl')  # Load your model here

    def initUI(self):
        self.setWindowTitle('Aegis DDoS Detection System')
        layout = QVBoxLayout()

        self.status_label = QLabel('Status: Idle')
        layout.addWidget(self.status_label)

        self.start_btn = QPushButton('Start Monitoring')
        self.start_btn.clicked.connect(self.startMonitoring)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton('Stop Monitoring')
        self.stop_btn.clicked.connect(self.stopMonitoring)
        layout.addWidget(self.stop_btn)

        self.attack_btn = QPushButton('Launch Test DDoS Attack')
        self.attack_btn.clicked.connect(self.launchAttack)
        layout.addWidget(self.attack_btn)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.resize(500, 400)

    def updateLog(self, message):
        self.log.append(message)

    def updateStatus(self, message):
        self.status_label.setText(f'Status: {message}')

    def startMonitoring(self):
        if not self.monitoring:
            self.monitoring = True
            self.comm.status_signal.emit("Monitoring")
            threading.Thread(target=self.captureTraffic, daemon=True).start()

    def stopMonitoring(self):
        self.monitoring = False
        self.comm.status_signal.emit("Stopped")

    def launchAttack(self):
        threading.Thread(target=self.scapyAttack, daemon=True).start()
        self.comm.log_signal.emit("[INFO] Launching Synthetic DDoS Attack...")


    def scapyAttack(self):
        target_ip = socket.gethostbyname(socket.gethostname())
        target_port = 80
        packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*1600)

        try:
          send(packet, count=50000, inter=0.00001, verbose=False)  # Reduced packet count for testing
          self.comm.log_signal.emit("[INFO] Attack packets sent successfully.")
        except Exception as e:
          self.comm.log_signal.emit(f"[ERROR] Failed to send packets: {str(e)}")
        threading.Thread(target=self.scapyAttack).start()

    def captureTraffic(self):
        asyncio.set_event_loop(asyncio.new_event_loop())  # FIX: Create event loop for the thread
    
        cap = pyshark.LiveCapture(interface='Wi-Fi')
        packet_count = 0
        byte_count = 0
        start_time = pd.Timestamp.now()

        for packet in cap.sniff_continuously():
            if not self.monitoring:
                break

            try:
                packet_count += 1
                byte_count += int(packet.length)
                elapsed = (pd.Timestamp.now() - start_time).total_seconds()

                if elapsed >= 1:  # Every second
                    avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
                    features = pd.DataFrame([{
                        'packet_count': packet_count,
                        'packet_count_per_second': packet_count / elapsed,
                        'byte_count': byte_count,
                        'byte_count_per_second': byte_count / elapsed
        
                    }])

                    prediction = self.model.predict(features)[0]

                    self.comm.log_signal.emit(f"Packets: {packet_count}, Bytes: {byte_count}, Status: {prediction}")
                    self.comm.log_signal.emit(f"Feature Values: {features.to_dict(orient='records')}")

                    if prediction == 'DDoS':
                        src_ip = packet.ip.src
                        self.comm.log_signal.emit(f"[ALERT] DDoS detected from {src_ip}, blocking IP...")
                        self.blockIP(src_ip)
                        self.comm.status_signal.emit("DDoS Blocked")

                    # Reset counters
                    packet_count = 0
                    byte_count = 0
                    start_time = pd.Timestamp.now()

            except Exception as e:
                continue

        cap.close()

    def blockIP(self, ip):
        try:
            subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in interface=any action=block remoteip={ip}', shell=True)
            self.comm.log_signal.emit(f"[INFO] Blocked IP: {ip}")
        except Exception as e:
            self.comm.log_signal.emit(f"[ERROR] Failed to block IP: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DDoSDetector()
    window.show()
    sys.exit(app.exec_())
