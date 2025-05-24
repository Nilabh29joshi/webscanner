import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import traceback
from scanner import WebVulnerabilityScanner
from utils import validate_url, sanitize_input
import psycopg2

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure database with fallback to SQLite
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    logger.warning("DATABASE_URL environment variable is not set! Using SQLite as fallback.")
    database_url = "sqlite:///owasp_scanner.db"
else:
    # Test if the PostgreSQL connection works
    try:
        # Extract connection parameters from the URL
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
            
        # Create a connection to test if PostgreSQL is accessible
        conn_parts = database_url.split("://")[1].split("@")
        auth = conn_parts[0].split(":")
        host_port_db = conn_parts[1].split("/")
        host_port = host_port_db[0].split(":")
        
        username = auth[0]
        password = auth[1] if len(auth) > 1 else ""
        host = host_port[0]
        port = host_port[1] if len(host_port) > 1 else "5432"
        dbname = host_port_db[1].split("?")[0]
        
        conn = psycopg2.connect(
            dbname=dbname,
            user=username,
            password=password,
            host=host,
            port=port
        )
        conn.close()
        logger.info("PostgreSQL connection successful. Using PostgreSQL database.")
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {str(e)}. Using SQLite as fallback.")
        database_url = "sqlite:///owasp_scanner.db"

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Import models after configuring app
from models import db, ScanHistory, RemediationTip
db.init_app(app)

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["50 per day", "10 per hour"]
)

# Create database tables with error handling
with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Add remediation tips if they don't exist yet
        if RemediationTip.query.count() == 0:
            logger.info("Adding remediation tips to database")
            remediation_tips = [
            {
                "vulnerability_name": "A1:2021 - Broken Access Control",
                "remediation_tips": "• Implement proper authentication for all sensitive endpoints\n• Use role-based access control (RBAC)\n• Deny access by default\n• Don't rely solely on obfuscation for protection\n• Implement API gateways and API keys for APIs\n• Rate limit API and controller access"
            },
            {
                "vulnerability_name": "A2:2021 - Cryptographic Failures",
                "remediation_tips": "• Encrypt all sensitive data at rest and in transit\n• Use TLS for all web traffic (HTTPS)\n• Use strong encryption algorithms and up-to-date protocols\n• Implement HSTS headers\n• Do not use legacy protocols like TLS 1.0/1.1, SSL\n• Store passwords using strong adaptive and salted hashing functions"
            },
            {
                "vulnerability_name": "A3:2021 - Injection",
                "remediation_tips": "• Use parameterized queries for database operations\n• Use an ORM with proper parameter binding\n• Validate and sanitize all user inputs\n• Escape special characters based on context\n• Use LIMIT for SQL queries to reduce damage potential\n• Implement Content Security Policy (CSP)"
            },
            {
                "vulnerability_name": "Cross-Site Scripting (XSS)",
                "remediation_tips": "• Implement Content Security Policy (CSP) headers\n• Use templating systems with automatic escaping\n• Sanitize all user inputs\n• Apply context-specific encoding when outputting data\n• Use modern frameworks that automatically escape XSS by design\n• Implement XSS-Protection headers"
            },
            {
                "vulnerability_name": "A5:2021 - Security Misconfiguration",
                "remediation_tips": "• Use a minimal platform without unnecessary features\n• Remove default accounts and change default passwords\n• Implement proper security headers\n• Keep all systems updated and patched\n• Segment application architecture\n• Send security directives to clients like Content-Security-Policy"
            },
            {
                "vulnerability_name": "A6:2021 - Vulnerable Components",
                "remediation_tips": "• Remove unused dependencies\n• Continuously inventory all components and their versions\n• Only obtain components from official sources\n• Monitor for libraries without maintenance or security patches\n• Establish security patch management process\n• Use SCA tools like OWASP Dependency-Check"
            },
            {
                "vulnerability_name": "A7:2021 - Authentication Failures",
                "remediation_tips": "• Implement multi-factor authentication\n• Do not deploy with default credentials\n• Implement weak-password checks\n• Rate limit login attempts to prevent brute force\n• Use a secure session management with strong session IDs\n• Implement server-side session validation"
            },
            {
                "vulnerability_name": "A8:2021 - Data Integrity",
                "remediation_tips": "• Use digital signatures for all code libraries and components\n• Implement Subresource Integrity (SRI) for third-party resources\n• Verify software supply chain components\n• Implement a review process for code and configuration changes\n• Only use trusted repositories and avoid untrusted CDN sources"
            },
            {
                "vulnerability_name": "A9:2021 - Logging and Monitoring",
                "remediation_tips": "• Ensure all login, access control, and server-side input validation failures are logged\n• Use a format that allows log management solutions to parse them\n• Ensure log data is encoded correctly to prevent injection\n• Include enough detail to identify suspicious activity\n• Implement centralized log management and monitoring\n• Set up alerts for suspicious activities"
            },
            {
                "vulnerability_name": "A10:2021 - SSRF",
                "remediation_tips": "• Sanitize and validate all client-supplied data\n• Enforce URL schema, port, and destination with a positive allow list\n• Do not send raw responses to clients\n• Disable HTTP redirections\n• Be aware of URL consistency to prevent attacks using DNS or similar\n• Segment remote resource access functionality in separate networks"
            },
            {
                "vulnerability_name": "Clickjacking Protection",
                "remediation_tips": "• Implement X-Frame-Options header with DENY or SAMEORIGIN value\n• Use Content-Security-Policy (CSP) with frame-ancestors directive\n• For older browsers, consider defense in depth with frame-breaking JavaScript\n• Avoid putting sensitive functionality on pages that might be framed"
            },
            {
                "vulnerability_name": "Unvalidated Redirects",
                "remediation_tips": "• Avoid using redirects and forwards when possible\n• If used, don't involve user parameters in calculating destination\n• If user parameters can't be avoided, ensure the supplied value is valid and authorized\n• Use a mapping value instead of the actual URL\n• Force all redirects to go through a confirmation page"
            },
            {
                "vulnerability_name": "Sensitive Information Exposure",
                "remediation_tips": "• Ensure no secrets, credentials or API keys are hardcoded or exposed in client-side code\n• Implement proper data classification and handling based on sensitivity\n• Mask or truncate sensitive data like credit card numbers\n• Remove comments containing sensitive information or debugging details\n• Use HTTP headers like Cache-Control to prevent browsers from storing sensitive data\n• Implement proper access controls for sensitive information\n• Encrypt sensitive data at rest and in transit"
            }
        ]
        
        for tip in remediation_tips:
            db.session.add(RemediationTip(
                vulnerability_name=tip["vulnerability_name"],
                remediation_tips=tip["remediation_tips"]
            ))
        
        db.session.commit()
        logger.info("Remediation tips added successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        # Continue execution even if database fails

@app.route('/health')
def health():
    """Health check endpoint for Render"""
    try:
        # Test database connection
        db.session.execute("SELECT 1").scalar()
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({"status": "unhealthy", "database": "disconnected", "error": str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/history')
def history():
    try:
        # Get all scan history records, ordered by most recent first
        scan_records = ScanHistory.query.order_by(ScanHistory.scan_date.desc()).all()
        return render_template('history.html', scan_records=scan_records)
    except Exception as e:
        logger.error(f"Error fetching scan history: {str(e)}")
        return render_template('error.html', message="Could not fetch scan history. Please try again later."), 500

@app.route('/scan', methods=['POST'])
@limiter.limit("2 per minute")
def scan():
    try:
        target_url = request.form.get('url', '')
        
        # Validate and sanitize input
        if not target_url or not validate_url(target_url):
            return jsonify({
                'error': 'Invalid URL provided. Please enter a valid URL.'
            }), 400

        # Prevent self-scanning
        if get_remote_address() in target_url:
            return jsonify({
                'error': 'Self-scanning is not allowed for security reasons.'
            }), 403

        target_url = sanitize_input(target_url)
        scanner = WebVulnerabilityScanner(target_url)
        scan_results = scanner.run_all_scans()
        
        # Calculate vulnerability count and security score
        vulnerability_count = sum(1 for scan in scan_results['scans'] if scan['vulnerable'])
        total_scans = len(scan_results['scans'])
        security_score = max(0, 100 - (vulnerability_count / total_scans * 100))
        
        # Add remediation tips to each scan result
        for scan in scan_results['scans']:
            tip = RemediationTip.query.filter_by(vulnerability_name=scan['name']).first()
            if tip:
                scan['remediation_tips'] = tip.remediation_tips
            else:
                scan['remediation_tips'] = "No specific remediation tips available."
        
        # Save scan to database
        new_scan = ScanHistory(
            target_url=target_url,
            vulnerability_count=vulnerability_count,
            security_score=security_score,
            scan_results=scan_results
        )
        db.session.add(new_scan)
        db.session.commit()
        
        # Redirect to results page
        return redirect(url_for('scan_results', scan_id=new_scan.id))

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return jsonify({
            'error': 'An error occurred during the scan. Please try again.'
        }), 500

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    try:
        scan = ScanHistory.query.get_or_404(scan_id)
        db.session.delete(scan)
        db.session.commit()
        return redirect(url_for('history'))
    except Exception as e:
        logger.error(f"Error deleting scan: {str(e)}")
        return render_template('error.html', message="Could not delete scan. Please try again later."), 500

@app.route('/results/<int:scan_id>')
def scan_results(scan_id):
    try:
        # Get the scan record from the database
        scan_record = ScanHistory.query.get_or_404(scan_id)
        
        return render_template('results.html', scan=scan_record)
    except Exception as e:
        logger.error(f"Error retrieving scan results: {str(e)}")
        return render_template('error.html', message="Could not retrieve scan results. Please try again later."), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', message="Internal server error"), 500

if __name__ == '__main__':
    # Use PORT environment variable for Render compatibility
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
