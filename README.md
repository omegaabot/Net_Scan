# 📡 Net_Scan: Concurrent Network Discovery and Port Scanner

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![MIT License](https://img.shields.io/github/license/omegaabot/Net_Scan)
![Last Commit](https://img.shields.io/github/last-commit/omegaabot/Net_Scan)
![Issues](https://img.shields.io/github/issues/omegaabot/Net_Scan)

A blazing-fast Python tool that finds every gadget on your network and scans their ports—like a digital game of hide and seek! Discover, scan, export, done. Perfect for curious minds, sysadmins, and anyone who loves a little network magic. 🚀

---

## 📋 Table of Contents

- [✨ Key Features](#-key-features)
- [⚡ Quick Start](#-quick-start)
- [🛠️ How It Works](#-how-it-works)
- [📁 Project Structure](#-project-structure)
- [⚙️ Installation & Usage](#️-installation--usage)
- [📊 Sample Output](#-sample-output)
- [🤝 Contributing](#-contributing)
- [👤 About the Author](#-about-the-author)
- [🚀 Future Features / TODO](#-future-features--todo)
- [📄 License](#-license)

---

## ✨ Key Features

- **Device Discovery:** Identifies all responsive hosts on a local subnet using ARP requests.
- **Concurrent Port Scanning:** Uses a ThreadPoolExecutor for super-fast, simultaneous port scans.
- **Flexible Scan Options:** Quick, full, and custom scan modes for any situation.
- **Data Export:** Saves all scan results to `scan_results.csv` for easy analysis.
- **User-Friendly CLI:** Progress bars and prompts for a smooth user experience.

---

## ⚡ Quick Start

```bash
git clone https://github.com/omegaabot/Net_Scan.git
cd Net_Scan
python -m venv env
source env/bin/activate   # On Windows use `env\Scripts\activate`
pip install -r requirements.txt
sudo python3 net_scan.py   # On Linux/macOS
# or
python net_scan.py         # On Windows (run as Administrator)
```

---

## 🛠️ How It Works

### 1. Device Discovery (ARP Scan)

- Scapy crafts an **ARP request** and broadcasts it on the local subnet.
- Collects ARP replies to detect live devices (IP & MAC).

### 2. Port Scanning (TCP Connect Scan)

- For each discovered IP, uses a thread pool for fast, concurrent scans.
- Attempts to connect to each port; reports open services.

---

## 📁 Project Structure

```
Net_Scan/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── net_scan.py
```

> *Tip:*  
> If you plan to write tests, add a `/tests` folder.

---

## ⚙️ Installation & Usage

1. **Clone the Repository**
   ```bash
   git clone https://github.com/omegaabot/Net_Scan.git
   cd Net_Scan
   ```

2. **Install Dependencies**
   ```bash
   python -m venv env
   source env/bin/activate   # On Windows: env\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the Scanner**
   - **Linux/macOS:**  
     `sudo python3 net_scan.py`
   - **Windows:**  
     Open as Administrator and run:  
     `python net_scan.py`

4. **Follow Prompts:**  
   Enter the target subnet and choose the scan type.

---

## 📊 Sample Output

```text
[*] Simple Network Scanner

Enter target subnet (e.g., 192.168.1.0/24): 192.168.1.0/24

--- Port Scan Options ---
q - Quick scan of common ports
f - Full scan of all 65,535 ports (very slow)
c - Custom scan of user-specified ports
Enter your choice [q]: q
[*] Quick scan selected.
[INFO] Discovering devices on 192.168.1.0/24...
[INFO] Discovered 3 device(s).

Scanning hosts for open ports...

Scanning hosts: 100%|██████████████████████████████████| 3/3 [00:02<00:00,  1.50it/s]
192.168.1.1 (a1:b2:c3:d4:e5:f6): [53, 80, 443]
192.168.1.102 (a2:b3:c4:d5:e6:f7): [8080]
192.168.1.105 (a3:b4:c5:d6:e7:f8): []

[✔] Results also saved to scan_results.csv
```
---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

- Fork the repo
- Create your feature branch (`git checkout -b feature/AmazingFeature`)
- Commit your changes (`git commit -m 'Add some AmazingFeature'`)
- Push to the branch (`git push origin feature/AmazingFeature`)
- Open a Pull Request

---

## 👤 About the Author

**Aditya Raj**  
- 🛡️ Cybersecurity Enthusiast
- 🐍 Python Developer
- [LinkedIn](https://www.linkedin.com/in/aditya-raj-516801256/) | [GitHub](https://github.com/omegaabot)

> “I’m still learning, but I’m building every day — one project at a time.”

---

## 🚀 Future Features / TODO

- [ ] Add UDP port scanning
- [ ] Add OS fingerprinting
- [ ] Export results in JSON format
- [ ] Web-based UI
- [ ] Scheduled/automated scans
- [ ] Improved error handling and reporting

---

## 📄 License

This project is licensed under the MIT License.  
Copyright (c) 2025 Aditya Raj
