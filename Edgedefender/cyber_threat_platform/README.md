# Enterprise Incident Response & Threat Correlation Platform (EIR-TCP)

## Problem Statement
Organizations face increasing cybersecurity threats. This platform provides a centralized solution for analyzing, correlating, and responding to incidents.

## Core Features
- Log analysis
- Malware detection
- Phishing URL analysis
- Incident reporting
- Role-based access control

## Architecture Overview
- **Backend**: Flask
- **Frontend**: HTML templates
- **Database**: SQLite
- **Security**: bcrypt, CSRF protection, secure sessions

## Security Practices Used
- Passwords hashed with bcrypt
- CSRF protection enabled
- Secure session cookies
- SECRET_KEY sourced from environment variables

## API Example
```bash
curl -X POST http://127.0.0.1:5000/api/analyze -d '{"url": "http://example.com"}' -H "Content-Type: application/json"
```

## How To Run
1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables: `export SECRET_KEY=your_secret_key`
3. Start the app: `python app.py`

## Scalability Plan
- Migrate to PostgreSQL for production
- Add caching with Redis
- Deploy on Kubernetes

## Future Improvements
- Add multi-factor authentication
- Integrate threat intelligence feeds
- Enhance reporting with visualizations