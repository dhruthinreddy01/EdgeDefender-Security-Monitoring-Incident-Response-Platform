import re
import sqlite3
from urllib.parse import urlparse

# Database connection setup
def get_db_connection():
    from os.path import dirname, join
    db_path = join(dirname(__file__), '../database/threat.db')
    return sqlite3.connect(db_path)

# Analyze phishing URL
def analyze_url(url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL provided.")

    # Check for suspicious patterns
    risk_score = 0
    classification = "Low"

    if has_suspicious_keywords(url):
        risk_score += 30
    if is_ip_based_url(url):
        risk_score += 40
    if has_excessive_subdomains(url):
        risk_score += 20
    if is_domain_length_anomalous(url):
        risk_score += 10

    # Classify risk level
    if risk_score >= 80:
        classification = "High"
    elif risk_score >= 50:
        classification = "Medium"

    # Store result in database
    store_url_scan(url, risk_score, classification)

    return {
        'url': url,
        'risk_score': risk_score,
        'classification': classification
    }

# Validate URL
def is_valid_url(url):
    regex = re.compile(
        r'^(http|https)://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(:\d+)?(?:/.*)?$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Check for suspicious keywords
def has_suspicious_keywords(url):
    suspicious_keywords = ["login", "verify", "secure", "update", "account"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

# Check if URL is IP-based
def is_ip_based_url(url):
    parsed_url = urlparse(url)
    return re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc) is not None

# Check for excessive subdomains
def has_excessive_subdomains(url):
    parsed_url = urlparse(url)
    domain_parts = parsed_url.netloc.split('.')
    return len(domain_parts) > 3

# Check for anomalous domain length
def is_domain_length_anomalous(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return len(domain) > 63

# Store URL scan result in the database
def store_url_scan(url, risk_score, classification):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute('''
        INSERT INTO url_scans (url, risk_score, classification)
        VALUES (?, ?, ?)
    ''', (url, risk_score, classification))

    connection.commit()
    connection.close()

if __name__ == "__main__":
    # Example usage
    test_url = "http://example.com/login"
    try:
        result = analyze_url(test_url)
        print("Phishing analysis result:", result)
    except ValueError as e:
        print(e)