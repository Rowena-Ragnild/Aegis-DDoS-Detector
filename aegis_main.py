import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QStackedWidget
from PyQt5.QtCore import Qt

class MainPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Aegis - Main Page")

        # Button to switch to Detection Page
        self.btn_open_detection = QPushButton("Launch Aegis Detector")
        self.btn_open_detection.clicked.connect(self.show_detection_gui)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.btn_open_detection)
        self.setLayout(layout)

    def show_detection_gui(self):
        """Switch to the DDoS Detection Page"""
        self.stacked_widget.setCurrentIndex(1)  # Switch to detection page

class DetectionPage(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Aegis")

        # Button to go back to Main Page
        self.btn_back = QPushButton("Back to Main Page")
        self.btn_back.clicked.connect(self.show_main_page)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.btn_back)
        self.setLayout(layout)

    def show_main_page(self):
        """Switch back to the Main Page"""
        self.stacked_widget.setCurrentIndex(0)  # Switch to main page

class AegisApp(QApplication):
    def __init__(self, sys_argv):
        super().__init__(sys_argv)
        self.stacked_widget = QStackedWidget()

        # Create instances of both pages
        self.main_page = MainPage(self.stacked_widget)
        self.detection_page = DetectionPage(self.stacked_widget)

        # Add both pages to the stacked widget
        self.stacked_widget.addWidget(self.main_page)  # Index 0
        self.stacked_widget.addWidget(self.detection_page)  # Index 1

        # Show the main page first
        self.stacked_widget.setCurrentIndex(0)
        self.stacked_widget.show()

if __name__ == "__main__":
    app = AegisApp(sys.argv)
    sys.exit(app.exec_())

