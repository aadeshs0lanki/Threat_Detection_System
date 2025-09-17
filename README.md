# 🛡️ Z+ Threat Detection System (Z+TDS)

A lightweight **Threat Detection & Response System** written in **pure Python**.  
It monitors network connections in real-time, detects suspicious activity, and alerts via console, logs, email, or Slack.  

✅ Runs on Windows, Linux, or macOS  

---

## 🔹 Features

- **Real-time monitoring** of active connections  
- Detects:
  - Suspicious ports (e.g., 4444, 6667, 31337, etc.)
  - Brute force / port scan attempts
  - Blacklisted IPs (customizable list)
- **Alert System**
  - Console alerts
  - Logs (`alerts.log`)
  - Email alerts (optional)
  - Slack notifications (optional)
- **Mitigation Options**
  - Quarantine mode (track offenders, escalate if repeated)
  - Auto-block IP (via firewall rules)
  - Auto-kill malicious processes
  - Auto-suggest safe block commands
- **Demo Mode** — simulate attacks for presentations  
- **Dashboard** — live console dashboard with alerts & quarantine list  

---

## 🔹 Installation

### 1. Clone the repository
```bash
git clone https://github.com/aadeshs0lanki/Threat_Detection_System.git
cd Threat_Detection_System
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the program
- Real-time monitoring:
```bash
python threat_detection.py --run
```
- Demo mode (fake alerts for testing/presentations):
```bash
python threat_detection.py --demo
```
- Show past alerts:
```bash
python threat_detection.py --show-log
```
- Export alerts to JSON:
```bash
python threat_detection.py --export-json
```
---

## 🔹 Demo Mode Example

Run:
```bash
python threat_detection.py --demo
```

Output:
```
[ALERT] Suspicious port 4444 accessed from 192.168.1.50
[ALERT] Blacklisted IP detected from 45.133.1.10
[ALERT] Possible brute force/scan detected from 10.0.0.99
```

---

## 🔹 Screenshots

📊 **Dashboard Example**
```
============================================================
   Z+ Threat Detection System
============================================================

Recent Alerts:
 - Tue Sep 17 12:10:45 2025 - Suspicious port 4444 accessed from 192.168.1.50
 - Tue Sep 17 12:10:47 2025 - Blacklisted IP detected from 45.133.1.10

Quarantine List:
   192.168.1.50 -> 1 strikes
   45.133.1.10 -> 1 strikes

(Press CTRL+C to stop)
``` 

---

## 🔹 Disclaimer

⚠️ **For educational purposes only.**  
This is **not a replacement** for professional security software.  
Use responsibly in controlled environments.  

---

## 🔹 License
MIT License © 2025
