# **📡 Concurrent Network Discovery and Port Scanner**

A simple and efficient command-line tool written in Python to discover active devices on a local network and scan them for open TCP ports. This project uses multithreading for fast and concurrent port scanning.

## **📋 Table of Contents**

* [✨ Key Features](https://www.google.com/search?q=%23-key-features)  
* [🛠️ How It Works](https://www.google.com/search?q=%23%EF%B8%8F-how-it-works)  
* [📁 Project Structure](https://www.google.com/search?q=%23-project-structure)  
* [⚙️ Installation & Usage](https://www.google.com/search?q=%23%EF%B8%8F-installation--usage)  
* [📊 Sample Output](https://www.google.com/search?q=%23-sample-output)  
* [📄 License](https://www.google.com/search?q=%23-license)

## **✨ Key Features**

* **Device Discovery:** Identifies all responsive hosts on a local subnet using ARP requests.  
* **Concurrent Port Scanning:** Leverages a ThreadPoolExecutor to scan multiple ports simultaneously, significantly reducing scan times.  
* **Flexible Scan Options:** Provides quick, full, and custom scan modes to suit different needs.  
* **Data Export:** Automatically saves all scan results to a scan\_results.csv file for logging and analysis.  
* **User-Friendly Interface:** A clean CLI with progress bars for a clear user experience.

## **🛠️ How It Works**

The tool operates in two distinct phases, using powerful Python libraries to achieve its goals.

### **1\. Device Discovery (ARP Scan)**

The discovery phase uses the **Scapy** library to find live hosts.

* An **ARP request** packet (ARP(pdst=target\_ip)) is crafted.  
* This packet is wrapped in an **Ethernet frame** with the destination MAC address set to ff:ff:ff:ff:ff:ff, which is the broadcast address. This ensures all devices on the local network receive the packet.  
* Scapy's srp() function sends the packet and listens for ARP replies.  
* Devices that are online will respond, and the script collects their IP and MAC addresses.

### **2\. Port Scanning (TCP Connect Scan)**

The scanning phase uses Python's built-in **socket** library and **concurrent.futures** module.

* For each discovered IP, a ThreadPoolExecutor is initialized to manage a pool of worker threads. This allows us to check many ports at once.  
* The socket.connect\_ex((ip, port)) method is used to attempt a connection. This method is non-blocking and returns 0 on success, indicating an **open port**.  
* This approach is reliable and doesn't require the elevated privileges that a more advanced SYN scan would need (though the ARP scan still does).

## **📁 Project Structure**

The repository is organized to be clean and easy to navigate.

network-scanner-project/  
├── .gitignore          \# Tells Git which files to ignore  
├── LICENSE             \# Project's license file (MIT)  
├── README.md           \# This file\!  
├── requirements.txt    \# Lists Python dependencies  
└── scanner.py          \# The main application script

## **⚙️ Installation & Usage**

Follow these steps to get the scanner running on your machine. Administrative privileges are required.

### **Clone the Repository**

git clone \[https://github.com/your-username/your-repo-name.git\](https://github.com/your-username/your-repo-name.git)  
cd your-repo-name

### **Install Dependencies**

It's recommended to use a virtual environment.

\# Create and activate a virtual environment (optional but recommended)  
python \-m venv env  
source env/bin/activate  \# On Windows use \`env\\Scripts\\activate\`

\# Install required packages  
pip install \-r requirements.txt

### **Run the Scanner**

**On Linux/macOS:**

sudo python3 scanner.py

On Windows:  
Open Command Prompt or PowerShell as an Administrator and run:  
python scanner.py

**Follow Prompts:** The application will then prompt you to enter the target subnet and choose a scan type.

## **📊 Sample Output**

\[\*\] Simple Network Scanner

Enter target subnet (e.g., 192.168.1.0/24): 192.168.1.0/24  
...  
\[✔\] Scan Complete. Results:  
\=========================  
  IP: 192.168.1.1 (a1:b2:c3:d4:e5:f6)  
  Open Ports: 53, 80, 443

  IP: 192.168.1.102 (a2:b3:c4:d5:e6:f7)  
  Open Ports: 8080

\[✔\] Results also saved to scan\_results.csv

## **📄 License**

This project is licensed under the MIT License.

Copyright (c) 2025 Aditya raj