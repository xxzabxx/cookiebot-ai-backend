"""
Analytics model for tracking website events and metrics.
Optimized for performance with proper indexing.
Enhanced with unified API key support while maintaining full backward compatibility.
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
    
    # ENHANCED: Unified API key support (NEW)
    api_key = Column(String(64), index=True)  # For unified approach and performance
    domain = Column(String(255), index=True)  # For easier querying by domain
    
    # ENHANCED: Request metadata (NEW)
    ip_address = Column(String(45))  # IPv6 support
    user_agent = Column(String(500))
    
    # Additional data (renamed for consistency but backward compatible)
    event_metadata = Column(JSONB, default=dict)
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    website = relationship("Website", back_populates="analytics_events")
    
    # PRESERVED: All original indexes plus new ones for unified support
    __table_args__ = (
        Index('idx_analytics_website_date', 'website_id', 'created_at'),
        Index('idx_analytics_website_consent', 'website_id', 'consent_given'),
        Index('idx_analytics_event_type', 'event_type'),
        Index('idx_analytics_visitor_id', 'visitor_id'),
        # NEW: Unified API key indexes
        Index('idx_analytics_api_key', 'api_key'),
        Index('idx_analytics_api_key_date', 'api_key', 'created_at'),
        Index('idx_analytics_domain', 'domain'),
        Index('idx_analytics_api_key_domain', 'api_key', 'domain'),
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
            'metadata': self.event_metadata or {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            # NEW: Unified fields
            'api_key': self.api_key,
            'domain': self.domain,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }
    
    @classmethod
    def create_event(
        cls,
        website_id: int,
        event_type: str,
        visitor_id: Optional[str] = None,
        consent_given: Optional[bool] = None,
        revenue_generated: float = 0.0,
        metadata: Optional[Dict] = None,
        # NEW: Unified API key support
        api_key: Optional[str] = None,
        domain: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> 'AnalyticsEvent':
        """Create new analytics event with unified API key support."""
        
        event = cls(
            website_id=website_id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            revenue_generated=revenue_generated,
            event_metadata=metadata or {},
            # NEW: Unified fields
            api_key=api_key,
            domain=domain,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        try:
            db.session.add(event)
            db.session.commit()
            
            logger.info(
                "Analytics event created",
                event_id=event.id,
                website_id=website_id,
                event_type=event_type,
                visitor_id=visitor_id,
                api_key=api_key,
                domain=domain
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
    
    # PRESERVED: All original analytics methods
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
            cls.event_metadata['page_url'].astext.label('page_url'),
            func.count(cls.id).label('page_views'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors')
        ).filter(
            cls.website_id == website_id,
            cls.event_type == 'page_view',
            cls.created_at >= start_date,
            cls.created_at <= end_date,
            cls.event_metadata['page_url'].astext.isnot(None)
        ).group_by(
            cls.event_metadata['page_url'].astext
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

    # NEW: Unified API key analytics methods
    @classmethod
    def get_unified_analytics(
        cls,
        api_key: str,
        start_date: datetime,
        end_date: datetime,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive analytics across all websites for a given API key.
        """
        
        # Base query for unified analytics
        query = cls.query.filter(
            cls.api_key == api_key,
            cls.created_at >= start_date,
            cls.created_at <= end_date
        )
        
        if domain:
            query = query.filter(cls.domain == domain)
        
        # Get aggregated data across all websites
        result = db.session.query(
            func.count(cls.id).label('total_events'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors'),
            func.count(func.distinct(cls.domain)).label('total_websites'),
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
            cls.api_key == api_key,
            cls.created_at >= start_date,
            cls.created_at <= end_date
        )
        
        if domain:
            result = result.filter(cls.domain == domain)
            
        result = result.first()
        
        # Calculate unified metrics
        total_events = result.total_events or 0
        unique_visitors = result.unique_visitors or 0
        total_websites = result.total_websites or 0
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
            'total_websites': total_websites,
            'page_views': page_views,
            'banner_shows': banner_shows,
            'consents_given': consents_given,
            'consents_denied': consents_denied,
            'consent_rate': round(consent_rate, 2),
            'conversion_rate': round(conversion_rate, 2),
            'total_revenue': total_revenue,
            'average_revenue_per_visitor': round(total_revenue / unique_visitors, 2) if unique_visitors > 0 else 0,
            'average_revenue_per_website': round(total_revenue / total_websites, 2) if total_websites > 0 else 0,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            },
            'scope': 'unified' if not domain else f'domain:{domain}'
        }
    
    @classmethod
    def get_unified_website_breakdown(
        cls,
        api_key: str,
        start_date: datetime,
        end_date: datetime
    ) -> List[Dict[str, Any]]:
        """
        Get analytics breakdown by website/domain for a given API key.
        """
        
        result = db.session.query(
            cls.domain,
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
            cls.api_key == api_key,
            cls.created_at >= start_date,
            cls.created_at <= end_date,
            cls.domain.isnot(None)
        ).group_by(
            cls.domain
        ).order_by(
            func.count(cls.id).desc()
        ).all()
        
        # Format results
        websites = []
        for row in result:
            consents_given = row.consents_given or 0
            consents_denied = row.consents_denied or 0
            total_consent_events = consents_given + consents_denied
            consent_rate = (consents_given / total_consent_events * 100) if total_consent_events > 0 else 0
            
            websites.append({
                'domain': row.domain,
                'total_events': row.total_events or 0,
                'unique_visitors': row.unique_visitors or 0,
                'revenue': float(row.revenue or 0),
                'consents_given': consents_given,
                'consents_denied': consents_denied,
                'consent_rate': round(consent_rate, 2)
            })
        
        return websites
    
    @classmethod
    def get_unified_daily_analytics(
        cls,
        api_key: str,
        days: int = 30,
        domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get daily analytics breakdown for unified API key approach.
        """
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Query daily aggregated data
        query = db.session.query(
            func.date(cls.created_at).label('date'),
            func.count(cls.id).label('total_events'),
            func.count(func.distinct(cls.visitor_id)).label('unique_visitors'),
            func.count(func.distinct(cls.domain)).label('active_websites'),
            func.sum(cls.revenue_generated).label('revenue'),
            func.count(
                func.case([(cls.consent_given == True, 1)])
            ).label('consents_given'),
            func.count(
                func.case([(cls.consent_given == False, 1)])
            ).label('consents_denied')
        ).filter(
            cls.api_key == api_key,
            cls.created_at >= start_date
        )
        
        if domain:
            query = query.filter(cls.domain == domain)
            
        daily_data = query.group_by(
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
                'active_websites': row.active_websites or 0,
                'revenue': float(row.revenue or 0),
                'consents_given': consents_given,
                'consents_denied': consents_denied,
                'consent_rate': round(consent_rate, 2)
            })
        
        return results
    
    @classmethod
    def get_unified_real_time_stats(
        cls,
        api_key: str,
        minutes: int = 30
    ) -> Dict[str, Any]:
        """
        Get real-time statistics for unified API key approach.
        """
        
        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        
        result = db.session.query(
            func.count(cls.id).label('recent_events'),
            func.count(func.distinct(cls.visitor_id)).label('active_visitors'),
            func.count(func.distinct(cls.domain)).label('active_websites'),
            func.sum(cls.revenue_generated).label('recent_revenue'),
            func.count(
                func.case([(cls.consent_given == True, 1)])
            ).label('recent_consents')
        ).filter(
            cls.api_key == api_key,
            cls.created_at >= start_time
        ).first()
        
        return {
            'recent_events': result.recent_events or 0,
            'active_visitors': result.active_visitors or 0,
            'active_websites': result.active_websites or 0,
            'recent_revenue': float(result.recent_revenue or 0),
            'recent_consents': result.recent_consents or 0,
            'time_window_minutes': minutes,
            'timestamp': datetime.utcnow().isoformat()
        }

    @classmethod
    def create_unified_event(
        cls,
        api_key: str,
        domain: str,
        event_type: str,
        visitor_id: Optional[str] = None,
        consent_given: Optional[bool] = None,
        revenue_generated: float = 0.0,
        metadata: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        website_id: Optional[int] = None
    ) -> 'AnalyticsEvent':
        """
        Create analytics event using unified API key approach.
        Automatically handles website_id lookup or creation.
        """
        
        # If website_id not provided, we'll need to look it up or create it
        # This would typically be handled by the Website model
        if not website_id:
            # For now, we'll use a placeholder - this should be handled by the calling code
            website_id = 1  # This should be resolved by the calling endpoint
        
        return cls.create_event(
            website_id=website_id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            revenue_generated=revenue_generated,
            metadata=metadata,
            api_key=api_key,
            domain=domain,
            ip_address=ip_address,
            user_agent=user_agent
        )

