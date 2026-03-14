import sqlite3
from datetime import datetime

# Database connection setup
def get_db_connection():
    from os.path import dirname, join
    db_path = join(dirname(__file__), '../database/threat.db')
    return sqlite3.connect(db_path)

# Correlate threats across logs, malware scans, and phishing scans
def correlate_threats():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch log alerts
    cursor.execute('SELECT id, source_ip, alert_type, severity FROM log_alerts')
    log_alerts = cursor.fetchall()

    # Fetch malware scans
    cursor.execute('SELECT id, sha256_hash, risk_score FROM malware_scans')
    malware_scans = cursor.fetchall()

    # Fetch phishing scans
    cursor.execute('SELECT id, url, risk_score FROM url_scans')
    phishing_scans = cursor.fetchall()

    incidents = []

    # Correlate log alerts with phishing scans
    for log in log_alerts:
        log_id, source_ip, alert_type, severity = log
        for phishing in phishing_scans:
            phishing_id, url, risk_score = phishing
            if source_ip in url:  # Simple correlation based on IP in URL
                description = f"Correlation found: {alert_type} and Phishing URL {url}"
                incidents.append(create_incident(description, severity + risk_score))

    # Correlate log alerts with malware scans
    for log in log_alerts:
        log_id, source_ip, alert_type, severity = log
        for malware in malware_scans:
            malware_id, sha256_hash, risk_score = malware
            if severity > 50:  # Example condition for correlation
                description = f"Correlation found: {alert_type} and Malware {sha256_hash}"
                incidents.append(create_incident(description, severity + risk_score))

    # Store incidents in the database
    store_incidents(incidents)
    connection.close()
    return incidents

# Create an incident entry
def create_incident(description, severity):
    severity = min(severity, 100)  # Cap severity at 100
    return {
        'description': description,
        'severity': severity,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

# Store incidents in the database
def store_incidents(incidents):
    connection = get_db_connection()
    cursor = connection.cursor()

    for incident in incidents:
        cursor.execute('''
            INSERT INTO incidents (timestamp, description, severity)
            VALUES (?, ?, ?)
        ''', (incident['timestamp'], incident['description'], incident['severity']))

    connection.commit()
    connection.close()

if __name__ == "__main__":
    # Example usage
    correlated_incidents = correlate_threats()
    print("Correlated incidents:", correlated_incidents)