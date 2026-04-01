# YASH XSS Framework

YASH XSS Framework is an advanced, cross-platform security scanning tool designed for discovering Cross-Site Scripting (XSS) vulnerabilities. Featuring both a powerful command-line interface and an intuitive Tkinter GUI wrapper, the tool automates reconnaissance and vulnerability testing.

## 🌟 Cross-Platform Support

This framework is built natively in Python and is fully supported on both **Windows** and **Linux**.

### How Cross-Platform works
* **Windows**: We bundle `.exe` binaries of popular Go-based reconnaissance tools (`gau`, `httpx`, `subfinder`) locally so it works out of the box.
* **Linux**: We built an autonomous "Fallback Mode"! If you do not have Go tools installed on Linux, the framework automatically uses lightweight Python libraries (`requests`, `crt.sh`) to perform the exact same reconnaissance without failing.

---

## 🚀 Installation & Usage

### 1. Prerequisites
You must have Python 3.8+ installed on your system.

Install the required python dependencies:
```bash
pip install -r requirements.txt
```

### 2. Linux Dependencies (Optional)
If you want to use the high-performance Go binaries instead of our Python fallback scripts on Linux, simply install them globally:
```bash
sudo apt install subfinder httpx-toolkit
go install github.com/lc/gau/v2/cmd/gau@latest
```

### 3. Running the Tool
Because this is built in Python, the start command is the exact same on Windows and Linux:

**To launch the Graphic User Interface (GUI):**
```bash
python yash_xss_gui.py
```

**To use the Core CLI scanner:**
```bash
python core/yash_xss.py -d target.com
```

---

## 🎯 Features
- ✅ **Automated Reconnaissance**: Finds subdomains and parameters autonomously.
- ✅ **Dynamic Payload Injecting**: Tests inputs, query parameters, and fragmented URIs against a curated payload library.
- ✅ **Multi-Threading**: Rapidly probes massive domain lists concurrently.
- ✅ **Fallback Engine**: Pure-python mode triggers when external dependencies aren't found.

---

## ⚠️ Legal Disclaimer
**This tool is strictly developed for educational purposes and authorized penetration testing only.** 
The author, Yash Thakor, and any contributors are **NOT responsible** for any misuse, damage, or illegal acts caused by this program. Do not use this framework against servers, networks, or applications that you do not own or have explicit, written permission to test. Unauthorized hacking is a crime and may result in severe legal consequences.
