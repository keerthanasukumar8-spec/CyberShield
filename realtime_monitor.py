
import time
from collections import defaultdict

LOG_FILE = "logs/security_logs.txt"

def monitor_logs():
    print("CYBERSHIELD REAL-TIME MONITORING STARTED")
    print("----------------------------------------")

    failed_attempts = defaultdict(int)

    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            parts = line.strip().split(",")

            if len(parts) != 4:
                continue

            timestamp, event, ip_address, username = parts

            if event == "LOGIN_FAILED":
                failed_attempts[ip_address] += 1

                print(f"[WARNING] Failed login detected!")
                print(f"IP Address: {ip_address}")
                print(f"Username: {username}")
                print(f"Attempts: {failed_attempts[ip_address]}")

                if failed_attempts[ip_address] >= 5:
                    print("[HIGH ALERT] Possible brute-force attack!")

            elif event == "LOGIN_SUCCESS":
                print(f"[INFO] Successful login from {ip_address}")

if __name__ == "__main__":
    monitor_logs()
