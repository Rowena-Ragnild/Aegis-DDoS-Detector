# Aegis DDoS Detector

**Aegis** is a prototype desktop application developed using Python, PyQt5, and machine learning for real-time detection and mitigation of Distributed Denial of Service (DDoS) attacks It incorporates live network monitoring, anomaly detection through a pre-trained ML model and automated mitigation using the system firewall. This is a proof of concept project intended to demonstrate how AI can assist in network monitoring and protection. With further expertise in networking and security, Aegis can be significantly enhanced and expanded.

##  Features

-  **Real-Time Monitoring** of live network traffic
-  **Traffic Analysis** using pre-trained ML (Random Forest Classifier)
-   **Automatic DDoS Detection** based on traffic anomalies
-  **Logs and displays** key traffic features including:
   - Packet count per second
   - Byte count per second
-  **Synthetic DDoS Injection** module for testing the model
-  **Simulated IP Blocking** upon attack detection
-  **Modern GUI** with Start/Stop controls and live logs
- **About Page** explaining the system and attack types

---

##  Tech Stack

- **Python 3.x**
- **PyQt5** for GUI
- **Scikit-learn** for ML model
- **PyShark** (Wireshark wrapper) for live packet sniffing
- **Pandas**, **joblib** for data handling and model integration

---
## Application Preview

The application interface provides a graphical dashboard with start/stop controls, real-time traffic logs and alerts for detected anomalies.

##  Installation & Setup

git clone https://github.com/Rowena-Ragnild/Aegis-DDoS-Detector.git

cd Aegis-DDoS-Detector

**Install the following dependencies:**

 - PyQt5
 - joblib
 - pandas
 - scikit-learn
 - pyshark

**Important Note On Scripts:**
This repository contains multiple Python scripts, which represent different developmental stages of the Aegis application. While experimenting with various implementations, some scripts had partial functionality or incomplete modules.

**The final working script is:** aegis_wb_test4.py

Run it using the terminal in Visual Studio Code (or any terminal with proper environment access).

**Note:** This application requires WinPcap or Npcap to be installed for packet capturing. Administrator privileges are required for IP blocking.

 **To run the application:**
 - On your VS Code terminal run the command 'python aegis_wb_test4.py'
 - The application window will open with Start and Stop buttons.
 - Click Start to begin real-time network traffic monitoring.
 - Click Stop to halt monitoring and close the log stream.
In the terminal, enter the command:
 attack
   
 - **Important:** This triggers the injection of synthetic DDoS-like traffic, which is passed to the trained machine learning model for evaluation. The model identifies the simulated high-volume traffic as abnormal         (malicious)  and the application initiates automatic mitigation by blocking the attacking IP address using Windows' built-in firewall rules. 
 Due to resource limitations and the scope of this prototype, a real DDoS attack was not simulated. Instead, the system is designed to respond to synthetic attacks that mimic extreme network loads, allowing for safe        testing and demonstration of detection and response logic. In simpler words, actual DDoS traffic isn’t generated; instead, artificially extreme values   are injected to mimic such traffic.
 (This application requires Npcap or WinPcap for packet capturing and must be run with administrator privileges to enable firewall rule changes)

##  Limitations

- The app monitors only local network traffic.
- Real-world attacks are not simulated, only synthetic samples are injected.
- Blocking is limited to Windows OS firewall using `netsh` command.

## Future Improvements

- Add real packet sniffing and mitigation for larger networks.
- Cross-platform support for Linux and macOS.
- Integrate logging and visualization for traffic trends.

Contributions and suggestions are welcome!

##  Acknowledgements

This project was built as part of an academic prototype and learning exercise.  
Special thanks to the developers and maintainers of the PyQt5, scikit-learn and PyShark libraries, whose tools were instrumental in the development of this project.

## Author

**Rowena Ragnild**  

---

*This is a prototype project built for educational and demonstration purposes only.*






