"""
Analytics model for tracking website events and metrics.
Optimized for performance with proper indexing.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DECIMAL, DateTime, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy import func
import structlog

from app.utils.database import db

logger = structlog.get_logger()


class AnalyticsEvent(db.Model):
    """Analytics event model for tracking user interactions."""
    
    __tablename__ = 'analytics_events'
    
    # Primary fields
    id = Column(Integer, primary_key=True)
    website_id = Column(Integer, ForeignKey('websites.id', ondelete='CASCADE'), nullable=False)
    
    # Event details
    event_type = Column(String(100), nullable=False)
    visitor_id = Column(String(255))
    consent_given = Column(Boolean)
    revenue_generated = Column(DECIMAL(10, 2), default=0.00)
    
    # Additional data
    metadata = Column(JSONB, default=dict)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    website = relationship("Website", back_populates="analytics_events")
    
    # Indexes for performance (defined at class level)
    __table_args__ = (
        Index('idx_analytics_website_date', 'website_id', 'created_at'),
        Index('idx_analytics_website_consent', 'website_id', 'consent_given'),
        Index('idx_analytics_event_type', 'event_type'),
        Index('idx_analytics_visitor_id', 'visitor_id'),
    )
    
    def __repr__(self):
        return f'<AnalyticsEvent {self.event_type} for website {self.website_id}>'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analytics event to dictionary."""
        return {
            'id': self.id,
            'website_id': self.website_id,
            'event_type': self.event_type,
            'visitor_id': self.visitor_id,
            'consent_given': self.consent_given,
            'revenue_generated': float(self.revenue_generated) if self.revenue_generated else 0.0,
            'metadata': self.metadata or {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def create_event(
        cls,
        website_id: int,
        event_type: str,
        visitor_id: Optional[str] = None,
        consent_given: Optional[bool] = None,
        revenue_generated: float = 0.0,
        metadata: Optional[Dict] = None
    ) -> 'AnalyticsEvent':
        """Create new analytics event."""
        
        event = cls(
            website_id=website_id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            revenue_generated=revenue_generated,
            metadata=metadata or {}
        )
        
        try:
            db.session.add(event)
            db.session.commit()
            
            logger.info(
                "Analytics event created",
                event_id=event.id,
                website_id=website_id,
                event_type=event_type,
                visitor_id=visitor_id
            )
            
            return event
            
        except Exception as e:
            db.session.rollback()
            logger.error(
                "Failed to create analytics event",
                website_id=website_id,
                event_type=event_type,
                error=str(e)
            )
            raise
    
    @classmethod
    def get_website_analytics(
        cls,
        website_id: int,
        start_date: datetime,
        end_date: datetime,
        event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive analytics for a website.
        Optimized query to avoid N+1 problems.
        """
        
        # Base query
        query = cls.query.filter(
            cls.website_id == website_id,
            cls.created_at >= start_date,
            cls.created_at <= end_date
        )
        
        if event_type:
            query = query.filter(cls.event_type == event_type)
        
        # Get aggregated data in a single query
        result = db.session.query(
            func.count(cls.id).label('total_events'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors'),
            func.sum(cls.revenue_generated).label('total_revenue'),
            func.count(
                func.case([(cls.consent_given == True, 1)])
            ).label('consents_given'),
            func.count(
                func.case([(cls.consent_given == False, 1)])
            ).label('consents_denied'),
            func.count(
                func.case([(cls.event_type == 'page_view', 1)])
            ).label('page_views'),
            func.count(
                func.case([(cls.event_type == 'banner_shown', 1)])
            ).label('banner_shows')
        ).filter(
            cls.website_id == website_id,
            cls.created_at >= start_date,
            cls.created_at <= end_date
        ).first()
        
        # Calculate metrics
        total_events = result.total_events or 0
        unique_visitors = result.unique_visitors or 0
        total_revenue = float(result.total_revenue or 0)
        consents_given = result.consents_given or 0
        consents_denied = result.consents_denied or 0
        page_views = result.page_views or 0
        banner_shows = result.banner_shows or 0
        
        # Calculate rates
        total_consent_events = consents_given + consents_denied
        consent_rate = (consents_given / total_consent_events * 100) if total_consent_events > 0 else 0
        
        conversion_rate = (total_consent_events / banner_shows * 100) if banner_shows > 0 else 0
        
        return {
            'total_events': total_events,
            'unique_visitors': unique_visitors,
            'page_views': page_views,
            'banner_shows': banner_shows,
            'consents_given': consents_given,
            'consents_denied': consents_denied,
            'consent_rate': round(consent_rate, 2),
            'conversion_rate': round(conversion_rate, 2),
            'total_revenue': total_revenue,
            'average_revenue_per_visitor': round(total_revenue / unique_visitors, 2) if unique_visitors > 0 else 0,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        }
    
    @classmethod
    def get_daily_analytics(
        cls,
        website_id: int,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get daily analytics breakdown for a website.
        """
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Query daily aggregated data
        daily_data = db.session.query(
            func.date(cls.created_at).label('date'),
            func.count(cls.id).label('total_events'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors'),
            func.sum(cls.revenue_generated).label('revenue'),
            func.count(
                func.case([(cls.consent_given == True, 1)])
            ).label('consents_given'),
            func.count(
                func.case([(cls.consent_given == False, 1)])
            ).label('consents_denied')
        ).filter(
            cls.website_id == website_id,
            cls.created_at >= start_date
        ).group_by(
            func.date(cls.created_at)
        ).order_by(
            func.date(cls.created_at)
        ).all()
        
        # Format results
        results = []
        for row in daily_data:
            consents_given = row.consents_given or 0
            consents_denied = row.consents_denied or 0
            total_consent_events = consents_given + consents_denied
            consent_rate = (consents_given / total_consent_events * 100) if total_consent_events > 0 else 0
            
            results.append({
                'date': row.date.isoformat(),
                'total_events': row.total_events or 0,
                'unique_visitors': row.unique_visitors or 0,
                'revenue': float(row.revenue or 0),
                'consents_given': consents_given,
                'consents_denied': consents_denied,
                'consent_rate': round(consent_rate, 2)
            })
        
        return results
    
    @classmethod
    def get_event_breakdown(
        cls,
        website_id: int,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, int]:
        """Get breakdown of events by type."""
        
        result = db.session.query(
            cls.event_type,
            func.count(cls.id).label('count')
        ).filter(
            cls.website_id == website_id,
            cls.created_at >= start_date,
            cls.created_at <= end_date
        ).group_by(
            cls.event_type
        ).all()
        
        return {row.event_type: row.count for row in result}
    
    @classmethod
    def get_top_pages(
        cls,
        website_id: int,
        start_date: datetime,
        end_date: datetime,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top pages by page views."""
        
        result = db.session.query(
            cls.metadata['page_url'].astext.label('page_url'),
            func.count(cls.id).label('page_views'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors')
        ).filter(
            cls.website_id == website_id,
            cls.event_type == 'page_view',
            cls.created_at >= start_date,
            cls.created_at <= end_date,
            cls.metadata['page_url'].astext.isnot(None)
        ).group_by(
            cls.metadata['page_url'].astext
        ).order_by(
            func.count(cls.id).desc()
        ).limit(limit).all()
        
        return [
            {
                'page_url': row.page_url,
                'page_views': row.page_views,
                'unique_visitors': row.unique_visitors
            }
            for row in result
        ]
    
    @classmethod
    def cleanup_old_events(cls, days_to_keep: int = 365) -> int:
        """Clean up old analytics events to manage database size."""
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        deleted_count = cls.query.filter(
            cls.created_at < cutoff_date
        ).delete()
        
        db.session.commit()
        
        logger.info(
            "Old analytics events cleaned up",
            deleted_count=deleted_count,
            cutoff_date=cutoff_date.isoformat()
        )
        
        return deleted_count

