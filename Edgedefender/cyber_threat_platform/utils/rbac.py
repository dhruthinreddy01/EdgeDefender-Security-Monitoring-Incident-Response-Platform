from functools import wraps
from flask import session, redirect, url_for, request, abort
import logging
import sys

# Configure logging for both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - User: %(username)s - Role: %(role)s - Action: %(action)s - IP: %(ip)s',
    handlers=[
        logging.FileHandler('audit.log'),
        logging.StreamHandler(sys.stdout)  # Add console logging
    ]
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get('user')
            if not user or user.get('role') not in roles:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(username, role, action, ip):
    logging.info('', extra={
        'username': username,
        'role': role,
        'action': action,
        'ip': ip
    })