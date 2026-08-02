# Red-team-automation-platform
A Flask-based Red Team Automation Platform that performs reconnaissance, port scanning using Nmap, web security header analysis, password strength evaluation, and automated PDF vulnerability report generation.

## Current Cybersential implementation

Cybersential is an educational Flask application for explicitly authorized assessments. The current workflow accepts one HTTP(S) URL, domain, or IP; keeps a host-only value for DNS/WHOIS and Nmap; and preserves the complete normalized URL, including explicit ports and safe paths, for HTTP security-header analysis. It scans TCP ports 1-1024 with a normal Nmap connect scan and generates a UUID-named A4 PDF report. Password analysis is a separate in-memory workflow; entered passwords are never saved, echoed, logged by the application, or included in reports.

The active service layer is in `services/`:

```text
services/
|-- reconnaissance.py
|-- port_scanner.py
|-- header_analyzer.py
|-- password_analyzer.py
|-- packet_inspector.py
|-- traffic_analyzer.py
`-- report_generator.py
```

### Deep Packet Inspection and Network Traffic Analysis

The optional `/dpi` workflow performs a passive, metadata-only observation on a
server-selected local interface. Captures are explicitly authorized, limited to
5-30 seconds (15 seconds by default) and 10-500 packets (200 by default), and
stop as soon as either limit is reached. PCAP files and raw payloads are never
stored. The result contains only timestamps, IP addresses, protocol and port
metadata, packet lengths, TCP flags, ICMP types, DNS query names, and an
estimate of encrypted traffic. Rule-based findings are educational heuristics
and are never confirmation of an attack.

On Windows, install [Npcap](https://npcap.com/) separately before using live
capture; administrator or equivalent capture permission may be required. The
application does not install drivers automatically. Capture only traffic on a
machine/network you own or for which you have explicit authorization; do not
capture shared, college, workplace, public Wi-Fi, or third-party traffic without
permission. HTTPS and other encrypted payloads remain encrypted.

Open `http://127.0.0.1:5000/dpi`, choose an interface, duration, and packet
limit, confirm the authorization checkbox, and start one bounded capture. A
UUID result page and metadata-only PDF are kept in a process-local store of at
most ten assessments.

The original `modules/` files remain in the repository for history but are no longer imported by `app.py`.

### Setup and run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Install the Nmap executable separately from <https://nmap.org/download.html> and ensure `nmap --version` works in a new terminal. The `python-nmap` package is only the Python adapter; the application shows a friendly setup message when the executable is unavailable.

### Verification

```powershell
python -m compileall -q app.py services tests
python -m unittest discover -s tests -v
python -m flask --app app routes
```

Use only localhost, a lab machine, or another target covered by explicit permission. Generated reports are stored in the git-ignored `reports/` directory and can be downloaded only through their UUID-based route.

# 🔴 Red Team Automation Platform

## 📌 Project Overview

The **Red Team Automation Platform** is a web-based cybersecurity tool designed to automate common penetration testing and reconnaissance tasks.
The platform integrates multiple security modules such as domain reconnaissance, port scanning, web security analysis, password strength evaluation, and automated vulnerability report generation.

The system is built using **Python, Flask, and Nmap**, providing an easy-to-use dashboard for running basic security assessments.

This project demonstrates the **workflow of a Red Team security assessment** in a simplified and educational form.

---

# ⚙️ Features

### 🔍 Reconnaissance Module

* Domain information gathering
* WHOIS lookup
* Target IP resolution

### 🔓 Port Scanner

* Scans open ports on the target system
* Uses **Nmap** for network scanning
* Detects port states (open / closed)

### 🌐 Web Security Scanner

* Checks important security headers such as:

  * X-Frame-Options
  * Content-Security-Policy
  * X-XSS-Protection

### 🔑 Password Strength Analyzer

* Evaluates password strength based on:

  * Length
  * Uppercase letters
  * Numbers
  * Special characters

### 📄 Automated Report Generator

* Generates **PDF security reports**
* Includes recon results, open ports, and security header findings

---

# 🧰 Tech Stack

| Technology | Purpose                   |
| ---------- | ------------------------- |
| Python     | Core programming language |
| Flask      | Backend web framework     |
| Nmap       | Network scanning          |
| Requests   | Web requests              |
| ReportLab  | PDF report generation     |
| HTML / CSS | Frontend dashboard        |

---

# 📁 Project Structure

```
red-team-platform
│
├── app.py
├── requirements.txt
│
├── modules
│   ├── recon.py
│   ├── port_scanner.py
│   ├── web_scanner.py
│   ├── password_analyzer.py
│   └── report_generator.py
│
├── templates
│   ├── index.html
│   └── result.html
│
├── static
│   └── style.css
│
└── reports
```

---

# 🚀 How to Run the Project

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/red-team-automation-platform.git
```

Navigate into the project folder:

```bash
cd red-team-automation-platform
```

---

### 2️⃣ Create Virtual Environment

```bash
python -m venv .venv
```

Activate the environment:

**Windows**

```bash
.venv\Scripts\activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Install Nmap

Download and install Nmap from the official website:

https://nmap.org/download.html

Verify installation:

```bash
nmap --version
```

---

### 5️⃣ Run the Application

```bash
python app.py
```

---

### 6️⃣ Open in Browser

```
http://127.0.0.1:5000
```

---

# 🧪 Example Test Targets

Use safe testing targets such as:

```
scanme.nmap.org
```

or

```
testphp.vulnweb.com
```

---

# ⚠️ Disclaimer

This project is developed **for educational purposes only**.
The tool should only be used on systems where you have **explicit permission** to perform security testing.

Unauthorized scanning of websites or networks may violate laws and regulations.

---

# 👨‍💻 Author

**Syed Aakif Zain**
Computer Science & Design Engineering Student
**Syed Junaid**
Information Science And Enineering Student

---

# ⭐ Future Improvements

* Subdomain enumeration module
* SQL injection detection
* Advanced vulnerability scanning
* User authentication system
* Modern dashboard UI
* Ad injection detection
* Prompt injection detection

---
