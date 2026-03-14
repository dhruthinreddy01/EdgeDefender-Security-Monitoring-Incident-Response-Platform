import os
import sqlite3
from datetime import datetime

def create_tables():
    db_path = os.path.join(os.path.dirname(__file__), 'threat.db')
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    # Create log_alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            destination_ip TEXT,
            port INTEGER,
            alert_type TEXT NOT NULL,
            severity INTEGER NOT NULL
        )
    ''')

    # Create malware_scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_name TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            entropy REAL,
            risk_score INTEGER NOT NULL
        )
    ''')

    # Create url_scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            classification TEXT NOT NULL
        )
    ''')

    # Create incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL,
            severity INTEGER NOT NULL
        )
    ''')

    connection.commit()
    connection.close()

if __name__ == "__main__":
    create_tables()
    print("Database schema created successfully.")