import csv
from datetime import datetime, timedelta
import sqlite3
import os

# Database connection setup
def get_db_connection():
    from os.path import dirname, join
    db_path = join(dirname(__file__), '../database/threat.db')
    return sqlite3.connect(db_path)

# Analyze logs for brute force and port scan detections
def analyze_logs(file_path):
    alerts = []
    
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        logs = [row for row in reader]

    # Brute force detection
    brute_force_attempts = {}
    for log in logs:
        if log['status'] == 'failed':
            source_ip = log['source_ip']
            timestamp = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
            if source_ip not in brute_force_attempts:
                brute_force_attempts[source_ip] = []
            brute_force_attempts[source_ip].append(timestamp)

    for ip, attempts in brute_force_attempts.items():
        attempts.sort()
        for i in range(len(attempts)):
            window = [t for t in attempts if t <= attempts[i] + timedelta(minutes=2)]
            if len(window) > 5:
                alerts.append({
                    'source_ip': ip,
                    'alert_type': 'Brute Force',
                    'severity': 40,
                    'timestamp': attempts[i].strftime('%Y-%m-%d %H:%M:%S')
                })
                break

    # Port scan detection
    port_scans = {}
    for log in logs:
        source_ip = log['source_ip']
        port = log['port']
        timestamp = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
        if source_ip not in port_scans:
            port_scans[source_ip] = {}
        if port not in port_scans[source_ip]:
            port_scans[source_ip][port] = timestamp

    for ip, ports in port_scans.items():
        if len(ports) > 5:
            alerts.append({
                'source_ip': ip,
                'alert_type': 'Port Scan',
                'severity': 50,
                'timestamp': min(ports.values()).strftime('%Y-%m-%d %H:%M:%S')
            })

    store_alerts(alerts)
    return alerts

# Store alerts in the database
def store_alerts(alerts):
    connection = get_db_connection()
    cursor = connection.cursor()

    for alert in alerts:
        cursor.execute('''
            INSERT INTO log_alerts (timestamp, source_ip, alert_type, severity)
            VALUES (?, ?, ?, ?)
        ''', (alert['timestamp'], alert['source_ip'], alert['alert_type'], alert['severity']))

    connection.commit()
    connection.close()

if __name__ == "__main__":
    # Example usage
    sample_file = os.path.join(os.path.dirname(__file__), '../sample_logs.csv')
    alerts = analyze_logs(sample_file)
    print("Alerts generated:", alerts)