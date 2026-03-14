from flask import Blueprint, render_template, session
from utils.rbac import login_required, role_required

# Initialize Blueprint
report_bp = Blueprint('report', __name__)

@report_bp.route('/reports')
@login_required
@role_required('SOC Analyst', 'Super Admin', 'Auditor')
def view_reports():
    return render_template('reports.html')

@report_bp.route('/reports/export')
@login_required
@role_required('Auditor', 'Super Admin')
def export_reports():
    # Logic to export reports
    return "Reports exported successfully!"