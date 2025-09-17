import psutil
import time
import smtplib
import requests
import json
import os
import argparse
import platform
import pyfiglet
import subprocess
from collections import defaultdict
from email.mime.text import MIMEText

# ===============================
# 1. Configuration
# ===============================
CONFIG = {
    "attempt_threshold": 10,
    "time_window": 10,
    "email": {
        "enabled": False,
        "sender": "your_email@gmail.com",
        "password": "your_app_password",
        "receiver": "receiver_email@gmail.com",
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587
    },
    "slack": {
        "enabled": False,
        "webhook_url": "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"
    },
    # New security modes
    "quarantine_enabled": True,   # enable quarantine mode
    "auto_suggest_enabled": True, # suggest commands instead of auto-block
    "auto_block_enabled": False,  # if True, will block automatically
    "auto_kill_enabled": False,   # if True, will kill processes locally
}

ALERT_LOG = "alerts.log"
BLACKLIST_FILE = "blacklist.txt"

suspicious_ports = [6667, 31337, 12345, 4444]

# Track activity
connection_tracker = defaultdict(list)
alerts = []
blacklist_ips = set()
quarantine_ips = defaultdict(int)  # quarantine list with counters


# ===============================
# 2. Helpers
# ===============================
def load_blacklist():
    global blacklist_ips
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklist_ips = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        blacklist_ips = set()


def send_email(subject, message):
    if not CONFIG["email"]["enabled"]:
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = CONFIG["email"]["sender"]
        msg["To"] = CONFIG["email"]["receiver"]

        server = smtplib.SMTP(CONFIG["email"]["smtp_server"], CONFIG["email"]["smtp_port"])
        server.starttls()
        server.login(CONFIG["email"]["sender"], CONFIG["password"])
        server.sendmail(CONFIG["email"]["sender"], CONFIG["receiver"], msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[ERROR] Email failed: {e}")


def send_slack(message):
    if not CONFIG["slack"]["enabled"]:
        return
    try:
        payload = {"text": message}
        requests.post(CONFIG["slack"]["webhook_url"], json=payload)
    except Exception as e:
        print(f"[ERROR] Slack failed: {e}")


def log_alert(message):
    full_msg = f"{time.ctime()} - {message}"
    alerts.append(full_msg)
    with open(ALERT_LOG, "a") as f:
        f.write(full_msg + "\n")
    print(f"[ALERT] {message}")
    send_email("Threat Detection Alert", message)
    send_slack(message)


# ===============================
# 3. Mitigation Features
# ===============================
def kill_process_by_ip(ip):
    terminated = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr and conn.raddr.ip == ip and conn.pid:
            try:
                p = psutil.Process(conn.pid)
                p.terminate()
                p.wait(timeout=3)
                terminated.append(conn.pid)
            except Exception as e:
                print(f"[WARN] Could not terminate pid {conn.pid}: {e}")
    return terminated


def block_ip(ip):
    system = platform.system().lower()
    try:
        if "linux" in system:
            subprocess.check_call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            subprocess.check_call(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
            return True
        elif "windows" in system:
            name = f"PTDS block {ip}"
            subprocess.check_call([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=in", "action=block", f"remoteip={ip}"
            ])
            subprocess.check_call([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", "dir=out", "action=block", f"remoteip={ip}"
            ])
            return True
        else:
            print("[INFO] Auto-block not supported on this OS.")
            return False
    except Exception as e:
        print(f"[ERROR] Blocking failed: {e}")
        return False


def suggest_block_command(ip):
    system = platform.system().lower()
    if "linux" in system:
        print(f"[SUGGEST] To block {ip}, run:")
        print(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"sudo iptables -A OUTPUT -d {ip} -j DROP")
    elif "windows" in system:
        print(f"[SUGGEST] To block {ip}, run:")
        print(f"netsh advfirewall firewall add rule name=\"PTDS block {ip}\" dir=in action=block remoteip={ip}")
        print(f"netsh advfirewall firewall add rule name=\"PTDS block {ip}\" dir=out action=block remoteip={ip}")
    else:
        print(f"[SUGGEST] Unknown OS. Please block {ip} manually.")


# ===============================
# 4. Threat Detection
# ===============================
def handle_threat(ip, reason):
    log_alert(f"{reason} from {ip}")

    # Quarantine first
    if CONFIG["quarantine_enabled"]:
        quarantine_ips[ip] += 1
        if quarantine_ips[ip] == 1:
            log_alert(f"IP {ip} moved to quarantine list (first strike).")
            return
        elif quarantine_ips[ip] == 2:
            log_alert(f"IP {ip} repeated suspicious activity (second strike).")

    # After quarantine strikes, take further action
    if CONFIG["auto_block_enabled"]:
        if block_ip(ip):
            log_alert(f"Firewall rules added to block {ip}")
    elif CONFIG["auto_suggest_enabled"]:
        suggest_block_command(ip)

    if CONFIG["auto_kill_enabled"]:
        killed = kill_process_by_ip(ip)
        if killed:
            log_alert(f"Terminated local processes {killed} for IP {ip}")


def detect_threats():
    connections = psutil.net_connections(kind="inet")
    current_time = time.time()

    for conn in connections:
        if conn.raddr:
            ip = conn.raddr.ip
            port = conn.raddr.port

            connection_tracker[ip].append(current_time)
            connection_tracker[ip] = [t for t in connection_tracker[ip] if current_time - t < CONFIG["time_window"]]

            # Rule 1: brute force / scan
            if len(connection_tracker[ip]) > CONFIG["attempt_threshold"]:
                handle_threat(ip, "Possible brute force/scan detected")

            # Rule 2: suspicious ports
            if port in suspicious_ports:
                handle_threat(ip, f"Suspicious port {port} accessed")

            # Rule 3: blacklisted IP
            if ip in blacklist_ips:
                handle_threat(ip, "Blacklisted IP detected")


# ===============================
# 5. Console Dashboard
# ===============================
def console_dashboard():
    os.system("cls" if os.name == "nt" else "clear")
    ascii_banner = pyfiglet.figlet_format("Z+TDS", font="lean")  # change font here
    print(ascii_banner)
    print("="*60)
    print(" Z+ Threat Detection System  ")
    print("="*60)
    print("\nRecent Alerts:")
    for alert in alerts[-10:]:
        print(f" - {alert}")
    print("\nQuarantine List:")
    for ip, count in quarantine_ips.items():
        print(f"   {ip} -> {count} strikes")
    print("\n(Press CTRL+C to stop)\n")


# ===============================
# 6. CLI Handling
# ===============================
def main():
    parser = argparse.ArgumentParser(description="Python Threat Detection System (PTDS)")
    parser.add_argument("--run", action="store_true", help="Run real-time monitoring")
    parser.add_argument("--show-log", action="store_true", help="Show past alerts")
    parser.add_argument("--export-json", action="store_true", help="Export alerts to alerts.json")
    args = parser.parse_args()

    load_blacklist()

    if args.show_log:
        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, "r") as f:
                print(f.read())
        else:
            print("No logs found yet.")
        return

    if args.export_json:
        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, "r") as f:
                data = [{"alert": line.strip()} for line in f]
            with open("alerts.json", "w") as out:
                json.dump(data, out, indent=4)
            print("Exported alerts to alerts.json")
        else:
            print("No logs found yet.")
        return

    if args.run:
        try:
            while True:
                detect_threats()
                console_dashboard()
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping Z+ Threat Detection System.")


if __name__ == "__main__":
    main()
