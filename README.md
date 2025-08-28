# 🛡️ Cyber Security Awareness — Training Demo

**Author:** @rubydoss  
**All Rights Reserved © 2025**

This project is an **educational cybersecurity toolkit** designed to raise awareness about **phishing attacks** and help students/employees learn safe practices.  
It includes:
- 🖥️ `app.py` → Flask-based **Phishing Training Login Page**
- 🔍 `phish_detect.py` → Python **Phishing URL Analyzer**
- 📚 Awareness tips & safe practices built-in

---

## 🚀 Features
- Fake **training login page** (educational only — no real credentials stored).
- Checks URL patterns: HTTPS, suspicious TLDs, hyphens, IP-based domains.
- Detects **forms posting to external domains**.
- Educates users with **tips on password safety & phishing awareness**.

---

## 🛠️ Installation & Usage
```bash
# Install requirements
pip install -r requirements.txt

# Run training site
python3 app.py
# Visit http://127.0.0.1:5000

# Run phishing analyzer
python3 phish_detect.py https://suspicious-site.com
