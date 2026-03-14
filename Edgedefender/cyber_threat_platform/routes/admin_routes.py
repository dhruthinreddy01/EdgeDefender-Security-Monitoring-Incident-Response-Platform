from flask import Blueprint, render_template, request, redirect, url_for, session, abort
from utils.rbac import login_required, role_required, log_action

# Initialize Blueprint
admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/dashboard')
@login_required
@role_required('Super Admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@admin_bp.route('/admin/user-management', methods=['GET', 'POST'])
@login_required
@role_required('Super Admin')
def user_management():
    if request.method == 'POST':
        # Handle user creation or role modification
        username = request.form['username']
        action = request.form['action']
        log_action(session['user']['username'], session['user']['role'], f'{action} user {username}', request.remote_addr)
    return render_template('user_management.html')