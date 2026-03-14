from flask import Blueprint, render_template, request, session
from utils.rbac import login_required, role_required, log_action

# Initialize Blueprint
analyst_bp = Blueprint('analyst', __name__)

@analyst_bp.route('/alerts')
@login_required
@role_required('SOC Analyst', 'Super Admin')
def view_alerts():
    return render_template('alerts.html')

@analyst_bp.route('/alerts/<int:alert_id>/mark', methods=['POST'])
@login_required
@role_required('SOC Analyst', 'Super Admin')
def mark_alert(alert_id):
    status = request.form['status']
    log_action(session['user']['username'], session['user']['role'], f'Marked alert {alert_id} as {status}', request.remote_addr)
    return redirect(url_for('analyst.view_alerts'))