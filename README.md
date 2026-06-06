# ⚡ N0wzy8 Bug Bounty Scanner

![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=yellow)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-Yes-cyan?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Recon%20%26%20Vulnerability-red?style=for-the-badge)

> **Fast, multi-threaded reconnaissance and vulnerability scanner engineered for efficient bug bounty hunting.**

---
## Screenshot

![Scanner](screenshots/main.png)
---
## 🚀 Features

### 🔍 Reconnaissance & Intelligence

| Module | Description |
|---|---|
| Subdomain Enumeration | Discovers hidden assets and expands attack surface |
| Technology Fingerprinting | Identifies backend stacks, CMS, and server software |
| Sensitive File Discovery | Scans for backups, `.env` files, and exposed configs |
| Directory Listing Detection | Flags misconfigured directories leaking server structure |
| Information Leak Detection | Extracts emails, internal IPs, and risky HTML comments |

### 🛡️ Vulnerability Assessment

| Module | Description |
|---|---|
| Reflected XSS | Scans parameters for cross-site scripting vulnerabilities |
| Open Redirect | Validates unsafe parameter-based redirections |
| CRLF Injection | Checks for HTTP response splitting potential |
| CORS Misconfiguration | Detects overly permissive cross-origin policies |
| Clickjacking & Headers | Analyzes missing security headers (`X-Frame-Options`, `CSP`, etc.) |
| Cookie Security | Flags missing `HttpOnly`, `Secure`, and `SameSite` attributes |
| Dangerous HTTP Methods | Tests for active `PUT`, `DELETE`, or `TRACE` methods |
| Rate Limiting | Evaluates server resilience against request flooding |

### ⚙️ Core Engine

- 🕷️ **Automatic Crawling** — Deep link extraction from targeted web applications
- 🔀 **Multi-threaded Architecture** — High-speed parallel scanning without bottlenecks
- 🎨 **Rich UI Output** — Clean, readable terminal output via the `rich` library
- 📄 **Auto-Reporting** — Structured `.txt` reports generated instantly on completion

---

## 📦 Installation

```bash
git clone https://github.com/n0wzy8/N0wzy8-BugBountyScanner.git
cd N0wzy8-BugBountyScanner
```

**Via pip:**

```bash
pip install -r requirements.txt
```

**Via Windows launcher:**

```bat
start.bat
```

> 💡 The launcher automatically verifies your Python installation, resolves missing dependencies, and kicks off the scanner.

---

## 🛠️ Usage

```bash
python main.py
```

**Target format examples:**

```
Domain only  →  example.com
Full URL     →  https://example.com
```

**Output location:**

```
output/[target_domain].txt
```

---

## 📋 Requirements

- Python 3.10+
- `requests`
- `beautifulsoup4`
- `dnspython`
- `rich`

---

## 💎 Support & Donations

If this tool helped you land a bounty, consider supporting future development:

| Currency | Address |
|---|---|
| ₿ BTC | `bc1qxrktzkjzdtemd02jcdx0mxw7u66hnulzn0ptqd` |
| 💎 ETH | `0x56d9C67B0eABf8946283C67F0fa8A32534e1Fe13` |
| 🐦 RVN | `RVYsBqVSGxu4qCq2UCLdpmoGjkdMbzfh1H` |

---

<p align="center">
  Made with ❤️ by <strong>N0wzy8</strong>
</p>
