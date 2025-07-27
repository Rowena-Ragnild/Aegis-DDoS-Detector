import sys
import asyncio
import threading
import joblib
import pandas as pd
from PyQt5.QtWidgets import QApplication, QWidget,QMainWindow, QPushButton, QVBoxLayout, QLabel, QTextEdit, QMessageBox
from PyQt5.QtCore import pyqtSignal, QObject, QTimer
import pyshark
import socket
import subprocess
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from scapy.all import IP, UDP, Raw, send
from PyQt5.QtWidgets import QVBoxLayout,QHBoxLayout
from PyQt5.QtGui import QPixmap
from PyQt5.QtGui import QFont


import random
import time

class Communicate(QObject):
    log_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

class DDoSDetector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.monitoring =False
        self.initUI()
        self.input_thread = threading.Thread(target=self.listen_for_input, daemon=True)
        self.input_thread.start()
       
       
        self.comm = Communicate()
        self.comm.log_signal.connect(self.updateLog)
        self.comm.status_signal.connect(self.updateStatus)
        self.model = joblib.load('retrained_model.pkl')  # Load your model here

    def listen_for_input(self):
        """Continuously listen for 'attack' command in the terminal"""
        while True:
            command = input().strip()  # Read user input from the terminal
            if command.lower() == "attack":
                self.launchAttack()

    
    """
    def initUI(self):
        self.setWindowTitle('Aegis-AI Powered DDoS Protection')
        self.setWindowIcon(QIcon('icons\shield.png'))
        layout = QVBoxLayout()
        title_label = QLabel('<h1 style="color:#4B0082;">🛡️ Aegis </h1>')
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)"""

    def initUI(self):
     self.setWindowTitle('Aegis - AI Powered DDoS Protection')
     self.setWindowIcon(QIcon(r'icons/shield.png'))  # Fixed path with forward slashes

     main_layout = QVBoxLayout()

    # --- Create Horizontal Layout for Icon + Title ---
     title_layout = QHBoxLayout()
     title_layout.setAlignment(Qt.AlignCenter)

    # Icon QLabel
     icon_label = QLabel()
     pixmap = QPixmap(r'icons/shield.png')  # Icon path
     pixmap = pixmap.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation)  # Resize icon
     icon_label.setPixmap(pixmap)
     icon_label.setAlignment(Qt.AlignCenter) 

    # Title QLabel
     """
     title_label = QLabel('<h1 style="color:#4B0082; font-size:120px; font-family:"Cinzel", serif;">Aegis</h1>')
     title_label.setAlignment(Qt.AlignCenter) """

     title_container = QVBoxLayout()
     title_container.setAlignment(Qt.AlignLeft)
     title_label = QLabel("Aegis")
     title_font = QFont("Cinzel", 50)  # Adjust font size as needed
     title_label.setFont(title_font)
     title_label.setStyleSheet("color: #4B0082;")  # Keep the color
     title_label.setAlignment(Qt.AlignLeft)

     subtitle_label = QLabel("AI Powered DDoS Protection")
     subtitle_font = QFont("Baskerville", 16)  # Adjust font & size as needed
     subtitle_label.setFont(subtitle_font)
     subtitle_label.setStyleSheet("color: #333333;")  # Dark gray for subtle contrast
     subtitle_label.setAlignment(Qt.AlignLeft)

    
     

    # Add icon and title to horizontal layout
     
     
     title_container.addWidget(title_label)
    
     title_container.addWidget(subtitle_label)
     title_layout.addWidget(icon_label)
     title_layout.addSpacing(10)
     title_layout.addLayout(title_container)
     """
     title_layout.addStretch() 
     title_layout.addWidget(icon_label)
     title_layout.addWidget(title_label)
     title_layout.addWidget(subtitle_label)
     title_layout.addStretch()"""
    

    # Add to main vertical layout
     main_layout.addLayout(title_layout)
     main_layout.addSpacing(20)
     
     dashboard_container = QWidget()
     dashboard_container.setFixedSize(1600, 700)
     dashboard_container.setStyleSheet("background-color: white; border-radius: 10px; padding: 10px;")
     dashboard_layout = QVBoxLayout(dashboard_container)
     dashboard_layout.setAlignment(Qt.AlignCenter)
     main_layout.addWidget(dashboard_container)
    # --- Set Layout ---
     container = QWidget()
     container.setLayout(main_layout)
     self.setCentralWidget(container)

     self.status_label = QLabel('Status: Idle')
     status_font = QFont("Arial", 14)  # Change "Arial" & size as needed
     self.status_label.setFont(status_font)
     self.status_label.setStyleSheet("color: #333333;") 
     main_layout.addWidget(self.status_label)
     

     self.start_btn = QPushButton('Start Monitoring')
     self.start_btn.setStyleSheet("""
    QPushButton {
        background-color: #81C784;  /* Light green */
        color: black;
        font-weight: bold;
        border-radius: 10px;
        padding: 5px;
    }
""")
     self.start_btn.setFixedWidth(300)
     self.start_btn.clicked.connect(self.startMonitoring)
     # Push everything down
     dashboard_layout.addWidget(self.start_btn, alignment=Qt.AlignCenter)

     self.stop_btn = QPushButton('Stop Monitoring')
     self.stop_btn.setStyleSheet("""
    QPushButton {
        background-color: #E57373;  /* Light red */
        color: black;
        font-weight: bold;
        border-radius: 10px;
        padding: 5px;
    }
""")
     self.stop_btn.setFixedWidth(300)
     self.stop_btn.clicked.connect(self.stopMonitoring)
     dashboard_layout.addWidget(self.stop_btn, alignment=Qt.AlignCenter)  # Center Stop button
     


     self.log = QTextEdit()
     self.log.setReadOnly(True)
     dashboard_layout.addWidget(self.log)
     main_layout.addStretch()
     main_layout.addWidget(dashboard_container,alignment=Qt.AlignCenter)
     main_layout.addStretch()
     container = QWidget()
     container.setLayout(main_layout)
     self.setStyleSheet("background-color: lavender;")
     self.setCentralWidget(container)


     
     self.resize(300, 200)
    

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
        print("DDoS Attack Launched!")  # Print in terminal
        self.setWindowTitle("DDoS Attack Detected!")
        threading.Thread(target=self.scapyAttack, daemon=True).start()
        
        self.comm.log_signal.emit(f"<span style='color:black; font-weight:bold;'> [INFO] Launching Synthetic DDoS Attack...</span>")
         # Inject extreme synthetic values for testing detection
        extreme_features = pd.DataFrame([{
            'packet_count': 16000,
            'packet_count_per_second': 4000,
            'byte_count': 1050000,
            'byte_count_per_second': 2050000
 }])

        prediction = self.model.predict(extreme_features)[0]

        self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[TEST] Injected Extreme Feature Values: {extreme_features.to_dict(orient='records')}</span>")
        self.comm.log_signal.emit(f"<span style='color:light blue; font-weight:bold;'>[TEST RESULT] Predicted Status: {prediction}</span>")
        

        if prediction == 'DDoS':
           self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[ALERT] Synthetic DDoS Detected</span>")
           self.comm.status_signal.emit("Synthetic DDoS Detected")
           detected_ips = {"192.168.1.200", "203.0.113.45","203.0.113.47","203.0.113.48","192.168.1.220"}
           self.mitigateAttack(detected_ips)
           

           
    """
    def scapyAttack(self):
        try:
            # Step 1: Generate synthetic extreme values
            packet_count = random.randint(80000, 120000)  # Total packets
            packet_count_per_second = random.randint(5000, 6000)  # Packets/sec

            target_ip = socket.gethostbyname(socket.gethostname())  # Get local IP dynamically
            target_port = 80

            desired_byte_count_per_sec = random.randint(200_000_000, 270_000_000)  # Bytes/sec
            packet_size = int(desired_byte_count_per_sec / packet_count_per_second)
            if packet_size < 100:
                packet_size = 100  # Avoid too small packets

            self.comm.log_signal.emit(f"<span style='color:#000080; font-weight:bold;'>[INFO] Attack Config: Packets: {packet_count}, Packets/sec: {packet_count_per_second}, Packet Size: {packet_size} bytes, Target: {target_ip}:{target_port}</span>")

            # Step 2: Create packet template
            packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load='X' * (packet_size - 42))  # Adjust payload

            # Step 3: Launch packets at controlled rate
            start_time = time.time()
            sent_packets = 0

            while sent_packets < packet_count:
                send(packet, verbose=0)
                sent_packets += 1

                # Control rate
                if sent_packets % packet_count_per_second == 0:
                    elapsed = time.time() - start_time
                    if elapsed < 1:
                        time.sleep(1 - elapsed)
                    start_time = time.time()

            self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[INFO] Synthetic DDoS attack completed. Total packets sent: {sent_packets}</span>")

        except Exception as e:
            self.comm.log_signal.emit(f"[ERROR] Attack failed: {str(e)}")"""
    def scapyAttack(self):
        try:
        # Step 1: Generate synthetic extreme values
           packet_count = random.randint(80000, 120000)  # Total packets
           packet_count_per_second = random.randint(5000, 6000)  # Packets/sec

           target_ip = socket.gethostbyname(socket.gethostname())  # Get local IP dynamically
           target_port = 80

           desired_byte_count_per_sec = random.randint(200_000_000, 270_000_000)  # Bytes/sec
           packet_size = int(desired_byte_count_per_sec / packet_count_per_second)
           if packet_size < 100:
             packet_size = 100  # Avoid too small packets

           self.comm.log_signal.emit(f"<span style='color:#000080; font-weight:bold;'>[INFO] Attack Config: Packets: {packet_count}, Packets/sec: {packet_count_per_second}, Packet Size: {packet_size} bytes, Target: {target_ip}:{target_port}</span>")

        # Step 2: Launch packets at controlled rate with random source IPs
           start_time = time.time()
           sent_packets = 0

           while sent_packets < packet_count:
            # Generate a random fake source IP
             fake_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

            # Create packet with spoofed source IP
             packet = IP(src=fake_ip, dst=target_ip) / UDP(dport=target_port) / Raw(load='X' * (packet_size - 42))

             send(packet, verbose=0)
             sent_packets += 1

            # Control rate
             if sent_packets % packet_count_per_second == 0:
                elapsed = time.time() - start_time
                if elapsed < 1:
                    time.sleep(1 - elapsed)
                start_time = time.time()

           self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[INFO] Synthetic DDoS attack completed. Total packets sent: {sent_packets}</span>")

        except Exception as e:
          self.comm.log_signal.emit(f"[ERROR] Attack failed: {str(e)}")

    """
    def mitigateAttack(self):
        self.comm.log_signal.emit(f"<span style='color:light blue; font-weight:bold;'>Mitigated Successfully!</span>")
        subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in interface=any action=block remoteip={ip}',
             shell=True)
        self.comm.log_signal.emit(f"[INFO] Blocked IP: {ip}")"""
    
    def mitigateAttack(self, detected_ips):
        """Blocks multiple detected attacking IPs dynamically using Windows Firewall."""
    
        if not detected_ips:
           self.comm.log_signal.emit(f"<span style='color:orange; font-weight:bold;'>No malicious IPs detected to block.</span>")
           return
    
        for ip in detected_ips:
            try:
        # Block the detected IP using Windows Firewall
              subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in interface=any action=block remoteip={ip}', shell=True)
              self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[INFO] Blocked IP: {ip}</span>")
            except Exception as e:
              self.comm.log_signal.emit(f"[ERROR] Failed to block {ip}: {str(e)}")

        self.comm.log_signal.emit(f"<span style='color:blue; font-weight:bold;'>Mitigation Completed Successfully!</span>")


    def captureTraffic(self):
        asyncio.set_event_loop(asyncio.new_event_loop())  # FIX: Create event loop for the thread

        interface = r'\Device\NPF_{79253990-4700-4DD4-85F4-77855D894693}'
        cap = pyshark.LiveCapture(interface=interface)

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
                        self.comm.log_signal.emit(f"<span style='color:red; font-weight:bold;'>[ALERT] DDoS detected from {src_ip}, blocking IP...</span>")
                        self.blockIP(src_ip)
                        self.comm.status_signal.emit(f"<span style='color:blue; font-weight:bold;'>DDoS Blocked</span>")

                    # Reset counters
                    packet_count = 0
                    byte_count = 0
                    start_time = pd.Timestamp.now()

            except Exception as e:
                continue

        cap.close()

    def blockIP(self, ip):
        try:
            subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in interface=any action=block remoteip={ip}',
             shell=True)
            self.comm.log_signal.emit(f"[INFO] Blocked IP: {ip}")
        except Exception as e:
            self.comm.log_signal.emit(f"[ERROR] Failed to block IP: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DDoSDetector()
    window.show()
    sys.exit(app.exec_())
