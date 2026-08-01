# Red-team-automation-platform
A Flask-based Red Team Automation Platform that performs reconnaissance, port scanning using Nmap, web security header analysis, password strength evaluation, and automated PDF vulnerability report generation.

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

