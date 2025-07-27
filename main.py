import sys
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QHBoxLayout, QStackedWidget, QDialog
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt,QTimer

class DDoSDetector:
    def __init__(self):
        self.model = self.load_model()

    def load_model(self):
        # Simulate loading model (replace with actual model loading logic)
        print("Model loaded successfully")
        return RandomForestClassifier()

    def predict_traffic(self, traffic_data):
        # Simulate prediction (replace with actual prediction logic)
        traffic_df = pd.DataFrame([traffic_data])
        # Add avg_packet_size if missing
        if 'avg_packet_size' not in traffic_df.columns:
            traffic_df['avg_packet_size'] = traffic_df['byte_count'] / traffic_df['packet_count']

        # Reorder columns
        traffic_df = traffic_df[['packet_count', 'packet_count_per_second', 'byte_count', 'byte_count_per_second', 'avg_packet_size']]

        # Simulate prediction (replace with actual model prediction)
        prediction = 'DDoS' if traffic_data['packet_count'] > 1000000 else 'Normal'
        return prediction

class AegisApp(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Aegis - AI-Powered DDoS Protection')
        self.setGeometry(100, 100, 600, 400)
        self.setStyleSheet("background-color: white;")
        
        # Setup DDoS Detector
        self.detector = DDoSDetector()

        # UI components
        self.initUI()

    def initUI(self):
        # Layout
        self.layout = QVBoxLayout()
        
        # Title Label
        self.title_label = QLabel('Aegis', self)
        self.title_label.setStyleSheet("font-size: 60px; color: darkpurple; font-weight: bold;")
        self.title_label.setAlignment(Qt.AlignCenter)
        
        # AI-Powered DDoS Protection
        self.subtitle_label = QLabel('AI - Powered DDoS Protection', self)
        self.subtitle_label.setStyleSheet("font-size: 20px; color: grey;")
        self.subtitle_label.setAlignment(Qt.AlignCenter)

        # Adding widgets to layout
        self.layout.addWidget(self.title_label)
        self.layout.addWidget(self.subtitle_label)

        # Add Stack View (for switching between pages)
        self.stack = QStackedWidget(self)

        # Page 1: About Page
        self.about_page = QWidget()
        self.about_layout = QVBoxLayout()
        self.about_text = QLabel(
            '''Aegis is an AI-powered system designed to detect and mitigate DDoS (Distributed Denial of Service) attacks in real-time.
            It uses machine learning to classify traffic as normal or malicious (DDoS). The system can also inject synthetic DDoS traffic
            for testing purposes, and once detected, it mitigates the attack by blocking the attacking IP address.'''
        )
        self.about_text.setWordWrap(True)
        self.about_layout.addWidget(self.about_text)
        self.about_page.setLayout(self.about_layout)

        # Page 2: Main Control Page (Start, Stop, Manual Testing)
        self.main_page = QWidget()
        self.main_layout = QVBoxLayout()

        # Button Layout
        self.button_layout = QHBoxLayout()
        
        self.start_button = QPushButton('Start Monitoring', self)
        self.stop_button = QPushButton('Stop Monitoring', self)
        self.manual_testing_button = QPushButton('Manual Testing', self)

        # Connect buttons to functions
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.manual_testing_button.clicked.connect(self.manual_testing)

        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)
        self.button_layout.addWidget(self.manual_testing_button)

        # Traffic Info
        self.traffic_info = QLabel('Traffic Status: Waiting...', self)
        self.traffic_info.setAlignment(Qt.AlignCenter)

        # Add buttons and traffic info to the main layout
        self.main_layout.addLayout(self.button_layout)
        self.main_layout.addWidget(self.traffic_info)

        self.main_page.setLayout(self.main_layout)

        # Adding Pages to Stack
        self.stack.addWidget(self.about_page)
        self.stack.addWidget(self.main_page)

        # Set the initial page (About Page)
        self.layout.addWidget(self.stack)
        self.setLayout(self.layout)

        # Switch to the main page after a short delay
        QTimer.singleShot(3000, self.switch_to_main_page)

    def switch_to_main_page(self):
        # Switch to the main page after 3 seconds (3000 milliseconds)
        self.stack.setCurrentIndex(1)

    def start_monitoring(self):
        self.traffic_info.setText("Traffic monitoring has started.")
        print("Traffic monitoring has started.")
        # Simulate traffic data for demonstration purposes
        traffic_data = {
            'packet_count': 1000000,
            'packet_count_per_second': 50000,
            'byte_count': 100000000,
            'byte_count_per_second': 8000000
        }

        # Predict traffic type
        traffic_type = self.detector.predict_traffic(traffic_data)
        print(f"Traffic Type Detected: {traffic_type}")

        self.traffic_info.setText(f"Traffic Status: {traffic_type} Traffic Detected")

    def stop_monitoring(self):
        self.traffic_info.setText("Traffic monitoring has stopped.")
        print("Traffic monitoring has stopped.")

    def manual_testing(self):
     self.traffic_info.setText("Manual testing started.")
     print("Injecting DDoS traffic for testing.")

    # Simulate DDoS traffic with extreme values
     traffic_data = {
        'packet_count': 5000000,  # Simulated DDoS traffic with a very high packet count
        'packet_count_per_second': 100000,  # Extreme packet rate per second
        'byte_count': 500000000,  # Very large byte count
        'byte_count_per_second': 10000000  # Extreme byte rate per second
    }

     print(f"Synthetic Traffic Data: {traffic_data}")

    # Predict traffic type
     traffic_type = self.detector.predict_traffic(traffic_data)
     print(f"Prediction for Synthetic Data: {traffic_type}")

     if traffic_type == 'DDoS':
        self.traffic_info.setText("DDoS Detected! Mitigation in Progress.")
        print("🚨 DDoS Detected! 🚨")

        # Simulate Mitigation (Block IP)
        self.mitigate_attack("192.168.1.100")  # Example IP to block
     else:
        self.traffic_info.setText("Normal Traffic Detected.")
        print("🌐 Normal traffic detected.")

        # Predict traffic type
        traffic_type = self.detector.predict_traffic(traffic_data)
        print(f"Traffic Type Detected: {traffic_type}")

        if traffic_type == 'DDoS':
            self.traffic_info.setText("DDoS Detected! Mitigation in Progress.")
            print("🚨 DDoS Detected! 🚨")

            # Simulate Mitigation (Block IP)
            self.mitigate_attack("192.168.1.100")  # Example IP to block
        else:
            self.traffic_info.setText("Normal Traffic Detected.")
            print("🌐 Normal traffic detected.")

    def mitigate_attack(self, ip_address):
        # Simulate blocking the attacking IP address
        print(f"Blocking IP: {ip_address}")
        self.traffic_info.setText(f"IP {ip_address} has been blocked.")

# Main Program Entry
if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AegisApp()
    window.show()
    sys.exit(app.exec_())
