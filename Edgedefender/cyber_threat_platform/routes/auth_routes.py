from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from utils.rbac import log_action
import logging

# Initialize Blueprint
auth_bp = Blueprint('auth', __name__)

# Initialize bcrypt and CSRF
bcrypt = Bcrypt()
csrf = CSRFProtect()

# Sample user data
users = {
    "admin": {"password": bcrypt.generate_password_hash("admin_pass").decode('utf-8'), "role": "Super Admin"},
    "analyst": {"password": bcrypt.generate_password_hash("analyst_pass").decode('utf-8'), "role": "SOC Analyst"},
    "auditor": {"password": bcrypt.generate_password_hash("auditor_pass").decode('utf-8'), "role": "Auditor"}
}

@auth_bp.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user'] = {'username': username, 'role': user['role']}
            log_action(username, user['role'], 'Login Success', request.remote_addr)
            return redirect(url_for('dashboard'))
        else:
            log_action(username, 'Unknown', 'Login Failure', request.remote_addr)
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    user = session.pop('user', None)
    if user:
        log_action(user['username'], user['role'], 'Logout', request.remote_addr)
    return redirect(url_for('auth.login'))