"""
Proper SQLAlchemy ComplianceScan model (if needed later)
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, JSON
from sqlalchemy.orm import relationship
from app.utils.database import db

class ComplianceScan(db.Model):
    """SQLAlchemy ComplianceScan model"""
    
    __tablename__ = 'compliance_scans'
    
    id = Column(Integer, primary_key=True)
    website_id = Column(Integer, ForeignKey('websites.id', ondelete='CASCADE'), nullable=False)
    scan_type = Column(String(100), nullable=False)
    status = Column(String(50), default='pending')
    results = Column(JSON)
    recommendations = Column(Text)
    compliance_score = Column(Integer, default=0)
    cookies_found = Column(Integer, default=0)
    scripts_found = Column(Integer, default=0)
    scan_url = Column(Text)
    scan_duration = Column(Integer)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Relationship back to website
    website = relationship("Website", back_populates="compliance_scans")
