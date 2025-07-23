"""
Analytics API endpoints with optimized queries and caching.
Fixes performance issues identified in the review.
FIXED: SQL BinaryExpression errors that caused registration failures.
"""
from datetime import datetime, timedelta
from typing import Dict, Any

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from app.models.user import User
from app.models.website import Website
from app.models.analytics import AnalyticsEvent
from app.utils.database import db
from app.utils.error_handlers import APIResponse, APIException, ErrorCodes
from app.utils.validators import validate_query_params, AnalyticsQuerySchema
from app.utils.cache import cached, analytics_cache_key

logger = structlog.get_logger()

# Create blueprint
analytics_bp = Blueprint('analytics', __name__)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)


@analytics_bp.route('/dashboard-summary', methods=['GET'])
@jwt_required()
@cached(ttl=300, key_func=lambda: f"dashboard_summary:{get_jwt_identity()}")
def get_dashboard_summary():
    """
    Get dashboard summary with optimized queries.
    Fixes N+1 query problems and implements caching.
    FIXED: SQL BinaryExpression errors.
    """
    try:
        current_user_id = int(get_jwt_identity())
        
        # Get user's websites with analytics in a single optimized query
        websites = Website.query.filter_by(user_id=current_user_id).all()
        
        if not websites:
            return APIResponse.success({
                'total_websites': 0,
                'total_visitors_today': 0,
                'total_revenue_today': 0.0,
                'average_consent_rate': 0.0,
                'recent_activity': []
            })
        
        website_ids = [w.id for w in websites]
        
        # Get today's analytics in a single query
        today = datetime.utcnow().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())
        
        # Optimized aggregation query
        from sqlalchemy import func, case
        
        # FIXED: Use func.sum(case((condition, 1), else_=0)) pattern
        today_stats = db.session.query(
            func.count(func.distinct(AnalyticsEvent.visitor_id)).label('unique_visitors'),
            func.coalesce(func.sum(AnalyticsEvent.revenue_generated), 0).label('total_revenue'),
            func.sum(case((AnalyticsEvent.consent_given.is_(True), 1), else_=0)).label('consents_given'),
            func.count(AnalyticsEvent.id).label('total_consent_events')
        ).filter(
            AnalyticsEvent.website_id.in_(website_ids),
            AnalyticsEvent.created_at >= today_start,
            AnalyticsEvent.created_at <= today_end
        ).first()
        
        # Calculate metrics
        total_visitors_today = today_stats.unique_visitors or 0
        total_revenue_today = float(today_stats.total_revenue or 0)
        consents_given = today_stats.consents_given or 0
        total_consent_events = today_stats.total_consent_events or 0
        
        average_consent_rate = (
            (consents_given / total_consent_events * 100) 
            if total_consent_events > 0 else 0
        )
        
        # Get recent activity (last 10 events)
        recent_events = AnalyticsEvent.query.filter(
            AnalyticsEvent.website_id.in_(website_ids)
        ).order_by(
            AnalyticsEvent.created_at.desc()
        ).limit(10).all()
        
        recent_activity = []
        for event in recent_events:
            website = next((w for w in websites if w.id == event.website_id), None)
            if website:
                recent_activity.append({
                    'event_type': event.event_type,
                    'website_domain': website.domain,
                    'created_at': event.created_at.isoformat(),
                    'consent_given': event.consent_given,
                    'revenue_generated': float(event.revenue_generated or 0)
                })
        
        return APIResponse.success({
            'total_websites': len(websites),
            'total_visitors_today': total_visitors_today,
            'total_revenue_today': total_revenue_today,
            'average_consent_rate': round(average_consent_rate, 2),
            'recent_activity': recent_activity
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get dashboard summary", user_id=current_user_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve dashboard summary",
            500
        )


@analytics_bp.route('/websites/<int:website_id>', methods=['GET'])
@jwt_required()
@validate_query_params(AnalyticsQuerySchema)
def get_website_analytics(website_id: int, validated_data: Dict[str, Any]):
    """
    Get detailed analytics for a specific website.
    Implements caching and optimized queries.
    """
    try:
        current_user_id = int(get_jwt_identity())
        start_date = validated_data['start_date']
        end_date = validated_data['end_date']
        event_type = validated_data.get('event_type')
        
        # Verify website ownership
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Convert dates to datetime
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        # Get comprehensive analytics
        analytics_data = AnalyticsEvent.get_website_analytics(
            website_id=website_id,
            start_date=start_datetime,
            end_date=end_datetime,
            event_type=event_type
        )
        
        # Get daily breakdown
        daily_data = AnalyticsEvent.get_daily_analytics(
            website_id=website_id,
            days=(end_date - start_date).days + 1
        )
        
        # Get event breakdown
        event_breakdown = AnalyticsEvent.get_event_breakdown(
            website_id=website_id,
            start_date=start_datetime,
            end_date=end_datetime
        )
        
        # Get top pages
        top_pages = AnalyticsEvent.get_top_pages(
            website_id=website_id,
            start_date=start_datetime,
            end_date=end_datetime,
            limit=10
        )
        
        return APIResponse.success({
            'website': website.to_dict(),
            'analytics': analytics_data,
            'daily_breakdown': daily_data,
            'event_breakdown': event_breakdown,
            'top_pages': top_pages
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get website analytics",
            website_id=website_id,
            user_id=current_user_id,
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve analytics data",
            500
        )


@analytics_bp.route('/websites/<int:website_id>/real-time', methods=['GET'])
@jwt_required()
def get_real_time_analytics(website_id: int):
    """Get real-time analytics for the last hour."""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Verify website ownership
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Get last hour's data
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        
        analytics_data = AnalyticsEvent.get_website_analytics(
            website_id=website_id,
            start_date=one_hour_ago,
            end_date=datetime.utcnow()
        )
        
        # Get recent events
        recent_events = AnalyticsEvent.query.filter(
            AnalyticsEvent.website_id == website_id,
            AnalyticsEvent.created_at >= one_hour_ago
        ).order_by(
            AnalyticsEvent.created_at.desc()
        ).limit(20).all()
        
        events_data = [event.to_dict() for event in recent_events]
        
        return APIResponse.success({
            'website': website.to_dict(),
            'real_time_analytics': analytics_data,
            'recent_events': events_data,
            'last_updated': datetime.utcnow().isoformat()
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get real-time analytics",
            website_id=website_id,
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve real-time analytics",
            500
        )


@analytics_bp.route('/export/<int:website_id>', methods=['GET'])
@jwt_required()
@limiter.limit("5 per hour")
@validate_query_params(AnalyticsQuerySchema)
def export_analytics(website_id: int, validated_data: Dict[str, Any]):
    """Export analytics data as CSV."""
    try:
        current_user_id = int(get_jwt_identity())
        start_date = validated_data['start_date']
        end_date = validated_data['end_date']
        
        # Verify website ownership
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Convert dates to datetime
        start_datetime = datetime.combine(start_date, datetime.min.time())
        end_datetime = datetime.combine(end_date, datetime.max.time())
        
        # Get all events for the period
        events = AnalyticsEvent.query.filter(
            AnalyticsEvent.website_id == website_id,
            AnalyticsEvent.created_at >= start_datetime,
            AnalyticsEvent.created_at <= end_datetime
        ).order_by(
            AnalyticsEvent.created_at.desc()
        ).all()
        
        # Convert to CSV format
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Date', 'Event Type', 'Visitor ID', 'Consent Given',
            'Revenue Generated', 'Metadata'
        ])
        
        # Write data
        for event in events:
            writer.writerow([
                event.created_at.isoformat(),
                event.event_type,
                event.visitor_id or '',
                event.consent_given if event.consent_given is not None else '',
                float(event.revenue_generated or 0),
                str(event.event_metadata or {})
            ])
        
        csv_data = output.getvalue()
        output.close()
        
        return APIResponse.success({
            'csv_data': csv_data,
            'filename': f"{website.domain}_analytics_{start_date}_{end_date}.csv",
            'total_events': len(events)
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to export analytics",
            website_id=website_id,
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to export analytics data",
            500
        )


@analytics_bp.route('/compare', methods=['GET'])
@jwt_required()
def compare_websites():
    """Compare analytics across multiple websites."""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Get query parameters
        website_ids = request.args.getlist('website_ids', type=int)
        days = int(request.args.get('days', 30))
        
        if not website_ids:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "At least one website ID is required",
                400
            )
        
        # Verify all websites belong to user
        websites = Website.query.filter(
            Website.id.in_(website_ids),
            Website.user_id == current_user_id
        ).all()
        
        if len(websites) != len(website_ids):
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "One or more websites not found",
                404
            )
        
        # Get analytics for each website
        start_date = datetime.utcnow() - timedelta(days=days)
        end_date = datetime.utcnow()
        
        comparison_data = []
        for website in websites:
            analytics = AnalyticsEvent.get_website_analytics(
                website_id=website.id,
                start_date=start_date,
                end_date=end_date
            )
            
            comparison_data.append({
                'website': website.to_dict(),
                'analytics': analytics
            })
        
        return APIResponse.success({
            'comparison': comparison_data,
            'period_days': days
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to compare websites", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to compare websites",
            500
        )

