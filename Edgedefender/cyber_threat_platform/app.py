import os
import logging
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename
from functools import wraps
import time

from core.log_analyzer import analyze_logs
from core.malware_analyzer import analyze_file
from core.phishing_analyzer import analyze_url
from core.report_generator import generate_report
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.analyst_routes import analyst_bp
from routes.report_routes import report_bp

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret_key")

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

REPORT_FOLDER = "reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Set the project name immediately after app initialization
app.config['PROJECT_NAME'] = 'Enterprise Incident Response & Threat Correlation Platform (EIR-TCP)'

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Sample user data
users = {
    "admin": {"password": bcrypt.generate_password_hash("admin_pass").decode('utf-8'), "role": "Admin"},
    "analyst": {"password": bcrypt.generate_password_hash("analyst_pass").decode('utf-8'), "role": "SOC_Analyst"},
    "auditor": {"password": bcrypt.generate_password_hash("auditor_pass").decode('utf-8'), "role": "Auditor"}
}

# Initialized missing variables.
alerts = []
malware_scans = []
url_scans = []
dashboard_metrics = {}

# Role-based access decorator
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return jsonify({"error": "Unauthorized access"}), 401
            user_role = session.get('role')
            if user_role not in roles:
                return jsonify({"error": "Forbidden: Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    # Example data for the dashboard
    total_alerts = 10
    high_severity = 3
    risk_labels = ['Low', 'Medium', 'High', 'Critical']
    risk_data = [2, 3, 3, 2]
    return render_template('dashboard.html', total_alerts=total_alerts, high_severity=high_severity, risk_labels=risk_labels, risk_data=risk_data)

@app.route('/upload_logs', methods=['GET', 'POST'])
def upload_logs():
    if request.method == 'POST':
        log_file = request.files['logFile']
        if log_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], log_file.filename)
            log_file.save(file_path)
            alerts = analyze_logs(file_path)
            flash('Log file analyzed successfully.', 'success')
            return render_template('upload_logs.html', alerts=alerts)
    return render_template('upload_logs.html')

@app.route('/upload_file', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        malware_file = request.files['malwareFile']
        if malware_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], malware_file.filename)
            malware_file.save(file_path)
            result = analyze_file(file_path)
            flash('File analyzed successfully.', 'success')
            return render_template('upload_file.html', result=result)
    return render_template('upload_file.html')

@app.route('/url_scan', methods=['GET', 'POST'])
def url_scan():
    if request.method == 'POST':
        url = request.form['url']
        result = analyze_url(url)
        flash('URL analyzed successfully.', 'success')
        return render_template('url_scan.html', result=result)
    return render_template('url_scan.html')

@app.route('/incidents', methods=['GET', 'POST'])
def incidents():
    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        output_file = os.path.join(REPORT_FOLDER, f'incident_report_{incident_id}.pdf')
        generate_report(output_file)
        flash(f'Report generated: {output_file}', 'success')
    # Example incidents data
    incidents = [
        {'id': 1, 'timestamp': '2026-03-03 10:00:00', 'description': 'Brute Force Attack', 'severity': 'High'},
        {'id': 2, 'timestamp': '2026-03-03 11:00:00', 'description': 'Phishing URL Detected', 'severity': 'Medium'}
    ]
    return render_template('incidents.html', incidents=incidents)

# REST API endpoints
@app.route('/api/alerts', methods=['GET'])
@role_required(["Admin", "SOC_Analyst"])
def get_alerts():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        paginated_alerts = paginate(alerts, page, per_page)
        return jsonify(paginated_alerts), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/incidents', methods=['GET'])
@role_required(["Admin", "SOC_Analyst"])
def get_incidents():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        paginated_incidents = paginate(incidents, page, per_page)
        return jsonify(paginated_incidents), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/malware-scans', methods=['GET'])
@role_required(["Admin", "SOC_Analyst"])
def get_malware_scans():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        paginated_scans = paginate(malware_scans, page, per_page)
        return jsonify(paginated_scans), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/url-scans', methods=['GET'])
@role_required(["Admin", "SOC_Analyst"])
def get_url_scans():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        paginated_scans = paginate(url_scans, page, per_page)
        return jsonify(paginated_scans), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard-metrics', methods=['GET'])
@role_required(["Admin", "Auditor"])
def get_dashboard_metrics():
    try:
        return jsonify(dashboard_metrics), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Pagination helper function
def paginate(data, page, per_page):
    start = (page - 1) * per_page
    end = start + per_page
    return data[start:end]

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username not in users:
        log_audit(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    user = users[username]
    if not bcrypt.check_password_hash(user['password'], password):
        log_audit(f"Failed login attempt for username: {username}")
        return jsonify({"error": "Invalid username or password"}), 401

    session['user'] = username
    session['role'] = user['role']
    log_audit(f"Successful login for username: {username}")
    return jsonify({"message": "Login successful", "role": user['role']}), 200

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

# Added a background thread to simulate real-time log generation and processing. Logs are automatically processed and the dashboard is updated dynamically.
def generate_logs():
    while True:
        # Simulate log generation
        log_entry = {"timestamp": "2026-03-03 10:00:00", "message": "Simulated log entry"}
        # Process the log entry
        analyze_logs(log_entry)
        time.sleep(5)

# Added Python logging for system and audit logs. Logs are stored in logs/system.log with error-level logging and audit trails for login attempts.
app.logger.setLevel('INFO')
app.logger.addHandler(logging.FileHandler('logs/system.log'))

# Added logging configuration for system and audit logs.
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
log_file = 'logs/system.log'
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s [%(levelname)s] %(message)s',
                    handlers=[RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)])

def log_audit(message):
    logging.getLogger('audit').info(message)

if __name__ == '__main__':
    app.run(debug=True)