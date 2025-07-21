"""
Website model with enhanced validation and relationships.
"""
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from sqlalchemy import Column, Integer, String, ForeignKey, DECIMAL, DateTime, Text
from sqlalchemy.orm import relationship
import structlog

from app.utils.database import db

logger = structlog.get_logger()


class Website(db.Model):
    """Website model for tracking user websites and their analytics."""
    
    __tablename__ = 'websites'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    domain = Column(String(255), nullable=False)
    client_id = Column(String(255), unique=True, nullable=False)
    
    # Status and metrics
    status = Column(String(50), default='pending', nullable=False)
    visitors_today = Column(Integer, default=0)
    consent_rate = Column(DECIMAL(5, 2), default=0.00)
    revenue_today = Column(DECIMAL(10, 2), default=0.00)
    
    # Integration
    integration_code = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="websites")
    analytics_events = relationship("AnalyticsEvent", back_populates="website", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Website {self.domain}>'
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.client_id:
            self.client_id = self.generate_client_id()
    
    @staticmethod
    def generate_client_id() -> str:
        """Generate unique client ID for website."""
        return f"cb_{uuid.uuid4().hex[:16]}"
    
    def generate_integration_code(self) -> str:
        """Generate JavaScript integration code for the website."""
        integration_code = f"""
<!-- CookieBot.ai Integration -->
<script>
(function() {{
    var cb = window.CookieBot = window.CookieBot || {{}};
    cb.clientId = '{self.client_id}';
    cb.apiUrl = 'https://cookiebot-ai-backend-production.up.railway.app/api/public';
    
    // Load CookieBot script
    var script = document.createElement('script');
    script.src = cb.apiUrl + '/script.js';
    script.async = true;
    document.head.appendChild(script);
}})();
</script>
<!-- End CookieBot.ai Integration -->
        """.strip()
        
        self.integration_code = integration_code
        return integration_code
    
    def update_daily_metrics(self, visitors: int = None, revenue: float = None) -> None:
        """Update daily metrics for the website."""
        if visitors is not None:
            self.visitors_today = visitors
        
        if revenue is not None:
            self.revenue_today = revenue
        
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Website metrics updated",
            website_id=self.id,
            domain=self.domain,
            visitors=self.visitors_today,
            revenue=float(self.revenue_today) if self.revenue_today else 0
        )
    
    def calculate_consent_rate(self) -> float:
        """Calculate consent rate based on recent analytics events."""
        from app.models.analytics import AnalyticsEvent
        
        # Get events from last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        total_events = AnalyticsEvent.query.filter(
            AnalyticsEvent.website_id == self.id,
            AnalyticsEvent.created_at >= thirty_days_ago,
            AnalyticsEvent.event_type.in_(['consent_given', 'consent_denied'])
        ).count()
        
        if total_events == 0:
            return 0.0
        
        consent_given = AnalyticsEvent.query.filter(
            AnalyticsEvent.website_id == self.id,
            AnalyticsEvent.created_at >= thirty_days_ago,
            AnalyticsEvent.consent_given == True
        ).count()
        
        consent_rate = (consent_given / total_events) * 100
        self.consent_rate = round(consent_rate, 2)
        
        return float(self.consent_rate)
    
    def get_analytics_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get analytics summary for the website."""
        from app.models.analytics import AnalyticsEvent
        from sqlalchemy import func
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get aggregated analytics
        result = db.session.query(
            func.count(AnalyticsEvent.id).label('total_events'),
            func.count(func.distinct(AnalyticsEvent.visitor_id)).label('unique_visitors'),
            func.sum(AnalyticsEvent.revenue_generated).label('total_revenue'),
            func.count(
                func.case([(AnalyticsEvent.consent_given == True, 1)])
            ).label('consents_given'),
            func.count(
                func.case([(AnalyticsEvent.consent_given == False, 1)])
            ).label('consents_denied')
        ).filter(
            AnalyticsEvent.website_id == self.id,
            AnalyticsEvent.created_at >= start_date
        ).first()
        
        total_events = result.total_events or 0
        unique_visitors = result.unique_visitors or 0
        total_revenue = float(result.total_revenue or 0)
        consents_given = result.consents_given or 0
        consents_denied = result.consents_denied or 0
        
        # Calculate consent rate
        total_consent_events = consents_given + consents_denied
        consent_rate = (consents_given / total_consent_events * 100) if total_consent_events > 0 else 0
        
        return {
            'total_events': total_events,
            'unique_visitors': unique_visitors,
            'total_revenue': total_revenue,
            'consent_rate': round(consent_rate, 2),
            'consents_given': consents_given,
            'consents_denied': consents_denied,
            'period_days': days
        }
    
    def to_dict(self, include_analytics: bool = False) -> Dict[str, Any]:
        """Convert website to dictionary for API responses."""
        data = {
            'id': self.id,
            'domain': self.domain,
            'client_id': self.client_id,
            'status': self.status,
            'visitors_today': self.visitors_today,
            'consent_rate': float(self.consent_rate) if self.consent_rate else 0.0,
            'revenue_today': float(self.revenue_today) if self.revenue_today else 0.0,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_analytics:
            data['analytics_summary'] = self.get_analytics_summary()
            data['integration_code'] = self.integration_code
        
        return data
    
    @classmethod
    def create_website(cls, user_id: int, domain: str) -> 'Website':
        """Create new website with validation."""
        # Normalize domain
        domain = domain.lower().strip()
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        # Check if website already exists for this user
        existing_website = cls.query.filter_by(
            user_id=user_id,
            domain=domain
        ).first()
        
        if existing_website:
            raise ValueError("Website already exists for this user")
        
        # Create new website
        website = cls(
            user_id=user_id,
            domain=domain,
            status='pending'
        )
        
        # Generate integration code
        website.generate_integration_code()
        
        try:
            db.session.add(website)
            db.session.commit()
            
            logger.info(
                "Website created",
                website_id=website.id,
                user_id=user_id,
                domain=domain,
                client_id=website.client_id
            )
            
            return website
            
        except Exception as e:
            db.session.rollback()
            logger.error("Failed to create website", user_id=user_id, domain=domain, error=str(e))
            raise
    
    def update_status(self, new_status: str) -> None:
        """Update website status with logging."""
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Website status updated",
            website_id=self.id,
            domain=self.domain,
            old_status=old_status,
            new_status=new_status
        )
    
    def delete_website(self) -> None:
        """Soft delete website by updating status."""
        self.status = 'deleted'
        self.updated_at = datetime.utcnow()
        
        logger.info(
            "Website deleted",
            website_id=self.id,
            domain=self.domain,
            user_id=self.user_id
        )

