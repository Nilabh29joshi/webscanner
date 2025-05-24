from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    vulnerability_count = db.Column(db.Integer, default=0)
    security_score = db.Column(db.Float, default=0)
    scan_results = db.Column(db.JSON, nullable=True)
    
    def __repr__(self):
        return f"<ScanHistory {self.id}: {self.target_url}>"

class RemediationTip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vulnerability_name = db.Column(db.String(100), nullable=False, unique=True)
    remediation_tips = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
        return f"<RemediationTip {self.vulnerability_name}>"