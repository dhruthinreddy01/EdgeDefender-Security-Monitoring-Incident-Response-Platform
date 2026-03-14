# EdgeDefender-Security-Monitoring-Incident-Response-Platform
EdgeDefender – Enterprise Security Monitoring & Incident Response Platform
Overview
EdgeDefender is a cybersecurity project that simulates a real-world Security Operations Center (SOC) environment by providing centralized log monitoring, rule-based threat detection, and incident response capabilities.
Modern organizations generate large volumes of security logs from systems such as firewalls, authentication servers, endpoints, and network infrastructure. Security teams must analyze these logs to identify suspicious activities and respond to potential threats.
EdgeDefender demonstrates how security monitoring systems work by collecting logs, analyzing events, detecting suspicious behavior, and presenting actionable alerts to security analysts.
This project focuses on practical cybersecurity concepts such as log analysis, threat detection engineering, incident correlation, and security monitoring architecture.
# Key Features
Centralized Log Collection
The platform collects logs from simulated enterprise infrastructure including:
Firewall logs
Authentication logs
Server activity logs
Network access logs
All logs are normalized into a structured format for analysis.
Rule-Based Threat Detection
The detection engine analyzes incoming logs and triggers alerts based on predefined security rules such as:
Multiple failed login attempts
Access from unusual IP addresses
Privilege escalation attempts
Login activity outside business hours
Suspicious outbound network connections
Incident Correlation
Instead of generating isolated alerts for every event, EdgeDefender groups related events together to form a single security incident, improving investigation efficiency.
Alert Prioritization
# Detected incidents are classified into severity levels:
Low
Medium
High
Critical
This helps analysts prioritize the most dangerous threats first.
SOC Monitoring Dashboard
A web dashboard provides security analysts with:
Real-time alert monitoring
Incident investigation panel
Log search capability
Security activity overview
Secure Access Control
The system implements Role-Based Access Control (RBAC) to manage analyst access to the platform.
System Architecture
The platform follows a modular architecture designed to simulate enterprise security monitoring systems.
# Components include:
Log Ingestion Layer – Collects and processes security logs
Detection Engine – Applies security rules and identifies suspicious events
Incident Correlation Module – Groups related alerts into incidents
Database – Stores logs and incident data
SOC Dashboard – Provides visualization and investigation interface
Authentication System – Manages secure analyst access
# Technologies Used
Backend
Python
FastAPI / Flask
Frontend
React.js
Database
MongoDB / PostgreSQL
Security
JWT Authentication
Role-Based Access Control (RBAC)
Other
REST APIs for system communication
Installation
Clone the repository:
git clone https:github.com/dhruthinreddy01/EdgeDefender-Security-Monitoring-Incident-Response-Platform
Navigate to the project directory:
cd EdgeDefender-SOC-Platform
Install dependencies:
pip install -r requirements.txt
Run the backend server:
python app.py
Start the frontend:
npm install
npm start
# EXAMPLE USE CASE
A user repeatedly attempts to log in with incorrect credentials.
The system detects multiple failed login attempts.
The detection engine triggers a security alert.
The incident correlation module groups related events.
The SOC dashboard displays the incident with severity level and investigation details.
This process simulates how real SOC teams detect and respond to potential cyber threats.
LEARNING OUTCOMES
# Through this project, the following cybersecurity concepts are demonstrated:
Security log analysis
Threat detection rule creation
Security incident correlation
SOC monitoring workflows
Alert prioritization and investigation
Secure application architecture
# FUTURE IMPROVEMENTS
Integration with SIEM platforms
Automated incident response actions
Machine learning-based anomaly detection
Real-time streaming log ingestion
Integration with threat intelligence feeds
