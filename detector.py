from collections import defaultdict


LOG_FILE = "logs/security_logs.txt"


def detect_threats():

    failed_attempts = defaultdict(int)

    with open(LOG_FILE, "r") as file:

        for line in file:

            parts = line.strip().split(",")

            if len(parts) != 4:
                continue

            timestamp, event, ip_address, username = parts

            if event == "LOGIN_FAILED":
                failed_attempts[ip_address] += 1

    print("\n===== CYBERSHIELD THREAT DETECTION =====\n")

    threats_found = False

    for ip_address, count in failed_attempts.items():

        if count >= 5:

            threats_found = True

            print("🔴 HIGH RISK THREAT DETECTED")
            print("IP Address:", ip_address)
            print("Failed Login Attempts:", count)
            print("Reason: Multiple failed login attempts")
            print("----------------------------------------")

    if not threats_found:
        print("No high-risk threats detected.")


if __name__ == "__main__":
    detect_threats()
