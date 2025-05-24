
---
# 🛡️ OWASP Top 10 Vulnerability Scanner

A comprehensive web-based security tool that scans websites for the OWASP Top 10 (2021) vulnerabilities and provides detailed reports with remediation suggestions.

---

## 📋 Features

- 🔍 **Complete OWASP Top 10 Coverage** (2021 edition)
- 🌙 **Dark-Themed UI** built with Bootstrap 5
- 📊 **Detailed Reporting** with severity indicators
- 🛠️ **Remediation Guidance** for each vulnerability
- 📁 **History Tracking** to view past scan results
- 🗄️ **Persistent Storage** using PostgreSQL

---

## 🛡️ Vulnerabilities Scanned

The scanner checks for the following:

- **A1:2021 - Broken Access Control**
- **A2:2021 - Cryptographic Failures**
- **A3:2021 - Injection** (SQL Injection, XSS)
- **A4:2021 - Insecure Design**
- **A5:2021 - Security Misconfiguration**
- **A6:2021 - Vulnerable and Outdated Components**
- **A7:2021 - Identification and Authentication Failures**
- **A8:2021 - Software and Data Integrity Failures**
- **A9:2021 - Security Logging and Monitoring Failures**
- **A10:2021 - Server-Side Request Forgery (SSRF)**

### 🔧 Additional Checks

- Clickjacking Protection
- Unvalidated Redirects
- Sensitive Information Exposure

---

## 🖥️ Screenshots

<!-- Add screenshots of your application here -->
*(To add screenshots, drag and drop images or link from `/assets` or hosted URLs)*

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- PostgreSQL

### Installation

```bash
git clone https://github.com/yourusername/owasp-scanner.git
cd owasp-scanner
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the root directory:

```env
DATABASE_URL=postgresql://username:password@localhost/owaspscanner
FLASK_SECRET_KEY=your_secure_secret_key
```

### Database Setup

```bash
flask db init
flask db migrate
flask db upgrade
```

### Running the App

```bash
gunicorn --bind 0.0.0.0:5000 --worker-class gevent main:app
```

Then open your browser and visit: [http://localhost:5000](http://localhost:5000)

---

## 📊 How It Works

1. **Input a URL**: Enter the target site in the scanner interface.
2. **Scan Execution**: Multiple security checks run on the target.
3. **Result Analysis**: Findings categorized by severity.
4. **Report Generation**: Detailed vulnerability report with fixes.
5. **Storage**: All scan results are saved to the database.

---

## ⚙️ Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: Bootstrap 5, JavaScript
- **Database**: PostgreSQL
- **Deployment**: Gunicorn + Gevent
- **Security Scanning**: Custom-built using OWASP methodologies

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security assessments** only. Always obtain explicit permission before scanning any system. Unauthorized use may violate laws in your region.

---

## 🤝 Contributing

Contributions are welcome!

```bash
# Fork and clone
git checkout -b feature/amazing-feature
# Make your changes
git commit -m "Add some amazing feature"
git push origin feature/amazing-feature
# Open a Pull Request
```

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org/)
- OWASP Top 10 for vulnerability classification
- All open-source libraries used in this project

```

---

Let me know if you’d like:
- GitHub Actions added for CI/CD
- Docker support instructions
- README badge suggestions (Build Passing, Python Version, etc.)

Want me to generate a cool project logo or banner for your GitHub page too?
