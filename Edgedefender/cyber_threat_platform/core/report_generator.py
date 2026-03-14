from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import sqlite3
import os

# Database connection setup
def get_db_connection():
    from os.path import dirname, join
    db_path = join(dirname(__file__), '../database/threat.db')
    return sqlite3.connect(db_path)

# Generate incident report PDF
def generate_report(output_path):
    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch incidents from the database
    cursor.execute('SELECT timestamp, description, severity FROM incidents ORDER BY timestamp DESC')
    incidents = cursor.fetchall()
    connection.close()

    # Create PDF document
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Incident Report", styles['Title']))
    elements.append(Spacer(1, 12))

    # Incident details
    for incident in incidents:
        timestamp, description, severity = incident
        elements.append(Paragraph(f"<b>Timestamp:</b> {timestamp}", styles['Normal']))
        elements.append(Paragraph(f"<b>Description:</b> {description}", styles['Normal']))
        elements.append(Paragraph(f"<b>Severity:</b> {severity}", styles['Normal']))
        elements.append(Spacer(1, 12))

    # Build PDF
    doc.build(elements)

if __name__ == "__main__":
    # Example usage
    output_file = os.path.join(os.path.dirname(__file__), '../reports/incident_report.pdf')
    try:
        generate_report(output_file)
    except Exception as e:
        pass