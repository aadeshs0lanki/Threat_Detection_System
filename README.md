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

### 1. Clone the repo
```bash
git clone https://github.com/aadeshs0lanki/Threat_Detection_System.git
cd Threat_Detection_System

### 2. Install dependencies

pip install -r requirements.txt

🔹 Usage

🔹 Run real-time monitoring

python threat_detection.py --run

🔹 Demo mode (safe, fake alerts for presentation)

python threat_detection.py --demo

🔹 Show past logs

python threat_detection.py --show-log

🔹 Export alerts to JSON (for reporting)

python threat_detection.py --export-json

# 🛡️ Z+ Threat Detection System (Z+TDS)

A lightweight **Threat Detection & Response System** written in **pure Python**.  
It monitors network connections in real-time, detects suspicious activity, and alerts via console, logs, email, or Slack.  
