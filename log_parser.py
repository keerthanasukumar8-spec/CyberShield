from collections import defaultdict

LOG_FILE = "logs/security_logs.txt"


def analyze_logs():

    total_logs = 0
    failed_logins = 0
    successful_logins = 0

    failed_attempts = defaultdict(int)
    ip_activity = defaultdict(int)
    logs = []

    with open(LOG_FILE, "r") as file:

        for line in file:

            parts = line.strip().split(",")

            if len(parts) != 4:
                continue

            timestamp, event, ip_address, username = parts

            total_logs += 1

            logs.append({
                "timestamp": timestamp,
                "event": event,
                "ip": ip_address,
                "username": username
            })

            if event == "LOGIN_FAILED":
                failed_logins += 1
                failed_attempts[ip_address] += 1
                ip_activity[ip_address] += 1

            elif event == "LOGIN_SUCCESS":
                successful_logins += 1

    alerts = []

    for ip_address, count in failed_attempts.items():

        if count >= 5:

            alerts.append({
                "ip": ip_address,
                "attempts": count,
                "severity": "HIGH",
                "reason": "Possible brute-force login attack"
            })

        elif count >= 3:

            alerts.append({
                "ip": ip_address,
                "attempts": count,
                "severity": "MEDIUM",
                "reason": "Repeated failed login attempts"
            })

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "alerts": alerts,
        "logs": logs,
        "ip_activity": dict(ip_activity)
    }