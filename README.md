# 🔍 Graphical Port Scanner with Vulnerability Insights

A Python-based port scanner with a graphical user interface (GUI) using Tkinter. This tool scans essential ports on a given IP address or domain name and provides filtered results with vulnerability information for popular services.

## 🎯 Key Features
- **Essential Port Scanning:** Scans critical ports like SSH, HTTP, HTTPS, FTP, DNS, etc.
- **Filtered Results:** Displays only open ports, filtering out closed ones for clarity.
- **Vulnerability Insights:** Shows potential vulnerabilities for each open service.
- **User-Friendly GUI:** Built using Tkinter for a simple and intuitive interface.
- **Domain/IP Support:** Works with both IP addresses and domain names.

## 🚀 How It Works
The scanner uses the **Nmap** library to perform the port scan. It focuses on the following essential ports:

- **Port 22**: SSH
- **Port 80**: HTTP
- **Port 443**: HTTPS
- **Port 21**: FTP
- **Port 53**: DNS
- **Port 25**: SMTP

Results are displayed in the GUI, highlighting the port state (open/closed) and the associated service.

### Steps:
1. Enter an IP address or domain in the input field.
2. Click "Start Scan" to begin.
3. The tool shows only open ports with their respective services and potential vulnerabilities.

## 🛠️ Installation
### Prerequisites
- Python 3.x
- Nmap (installed on your system)
- Required libraries: `nmap`, `tkinter`, `socket`, `threading`

### Setup
1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/port-scanner-gui.git
    cd port-scanner-gui
    ```
2. Install dependencies:
    ```bash
    pip install python-nmap
    ```

3. Run the script:
    ```bash
    python port_scanner.py
    ```

## 🖥️ Usage
1. Input the target IP address or domain name.
2. Click "Start Scan" and wait for the process to complete.
3. View the filtered results showing only open ports with their services.

## 📸 Screenshots
![Port Scanner Screenshot]
![image](https://github.com/user-attachments/assets/552b61df-ddc2-45f2-ab49-f8213db45c85)

## 🧑‍💻 Contributing
Pull requests are welcome. For major changes, please open an issue to discuss what you would like to change.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

## 📝 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
