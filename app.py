
from flask import Flask, render_template, Response
import csv
import io
from log_parser import analyze_logs

app = Flask(__name__)



@app.route("/export")
def export_logs():
    data = analyze_logs()
    logs = data["logs"]

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Timestamp", "Event", "IP Address", "Username"])

    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("event", ""),
            log.get("ip", ""),
            log.get("username", "")
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=cybershield_logs.csv"
        }
    )
@app.route("/")
def dashboard():
    data = analyze_logs()

    total_logs = data["total_logs"]
    failed_logins = data["failed_logins"]
    successful_logins = data["successful_logins"]
    alerts = data["alerts"]
    logs = data["logs"]
    ip_activity = data["ip_activity"]

    high_risk = 0
    medium_risk = 0

    for alert in alerts:
        if alert["severity"] == "HIGH":
            high_risk += 1
        elif alert["severity"] == "MEDIUM":
            medium_risk += 1

    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        alert_count=len(alerts),
        high_risk=high_risk,
        medium_risk=medium_risk,
        alerts=alerts,
        logs=logs,
        ip_activity=ip_activity
    )


if __name__ == "__main__":
    app.run(debug=True)
