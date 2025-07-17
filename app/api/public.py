"""
Public API endpoints for website tracking and analytics collection.
These endpoints are called by the JavaScript integration code.
"""
from datetime import datetime
from typing import Dict, Any

from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from app.models.website import Website
from app.models.analytics import AnalyticsEvent
from app.utils.database import db
from app.utils.error_handlers import APIResponse, APIException, ErrorCodes
from app.utils.validators import validate_json, AnalyticsEventSchema

logger = structlog.get_logger()

# Create blueprint
public_bp = Blueprint('public', __name__)

# Rate limiting for public endpoints
limiter = Limiter(key_func=get_remote_address)


@public_bp.route('/track', methods=['POST'])
@limiter.limit("1000 per hour")
@validate_json(AnalyticsEventSchema)
def track_event(validated_data: Dict[str, Any]):
    """
    Track analytics event from website integration.
    This is the main endpoint called by the JavaScript code.
    """
    try:
        client_id = validated_data['client_id']
        event_type = validated_data['event_type']
        visitor_id = validated_data.get('visitor_id')
        consent_given = validated_data.get('consent_given')
        revenue_generated = validated_data.get('revenue_generated', 0)
        metadata = validated_data.get('metadata', {})
        
        # Find website by client_id
        website = Website.query.filter_by(client_id=client_id).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Invalid client ID",
                404
            )
        
        # Check if website is active
        if website.status != 'active':
            raise APIException(
                ErrorCodes.RESOURCE_FORBIDDEN,
                "Website tracking is not active",
                403
            )
        
        # Add request metadata
        metadata.update({
            'ip_address': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'referer': request.headers.get('Referer', ''),
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Create analytics event
        event = AnalyticsEvent.create_event(
            website_id=website.id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            revenue_generated=revenue_generated,
            metadata=metadata
        )
        
        # Update website daily metrics if needed
        if event_type == 'page_view':
            # This could be optimized with background tasks
            website.visitors_today = website.visitors_today + 1
            
        if revenue_generated > 0:
            website.revenue_today = (website.revenue_today or 0) + revenue_generated
            
            # Add revenue to user balance (with revenue share)
            user = website.user
            revenue_share = 0.7  # 70% to user, 30% to platform
            user_revenue = revenue_generated * revenue_share
            user.add_revenue(user_revenue, f"Revenue from {website.domain}")
        
        website.updated_at = datetime.utcnow()
        db.session.commit()
        
        return APIResponse.success({
            'event_id': event.id,
            'status': 'tracked'
        }, "Event tracked successfully")
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to track event",
            client_id=validated_data.get('client_id'),
            event_type=validated_data.get('event_type'),
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to track event",
            500
        )


@public_bp.route('/script.js', methods=['GET'])
def get_tracking_script():
    """
    Serve the JavaScript tracking script.
    This script is loaded by websites to enable tracking.
    """
    script_content = """
(function() {
    'use strict';
    
    var CookieBot = window.CookieBot || {};
    
    // Configuration
    var config = {
        apiUrl: CookieBot.apiUrl || 'https://cookiebot-ai-backend-production.up.railway.app/api/public',
        clientId: CookieBot.clientId,
        debug: false
    };
    
    // Utility functions
    function generateVisitorId() {
        var stored = localStorage.getItem('cb_visitor_id');
        if (stored) return stored;
        
        var id = 'cb_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
        localStorage.setItem('cb_visitor_id', id);
        return id;
    }
    
    function trackEvent(eventType, data) {
        if (!config.clientId) {
            console.warn('CookieBot: Client ID not configured');
            return;
        }
        
        var payload = {
            client_id: config.clientId,
            event_type: eventType,
            visitor_id: generateVisitorId(),
            metadata: {
                page_url: window.location.href,
                page_title: document.title,
                timestamp: new Date().toISOString()
            }
        };
        
        // Merge additional data
        if (data) {
            Object.keys(data).forEach(function(key) {
                payload[key] = data[key];
            });
        }
        
        // Send to API
        fetch(config.apiUrl + '/track', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        }).catch(function(error) {
            if (config.debug) {
                console.error('CookieBot tracking error:', error);
            }
        });
    }
    
    // Auto-track page view
    trackEvent('page_view');
    
    // Cookie banner functionality
    function showCookieBanner() {
        if (localStorage.getItem('cb_consent_given') !== null) {
            return; // Already responded
        }
        
        var banner = document.createElement('div');
        banner.id = 'cookiebot-banner';
        banner.style.cssText = `
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #2c3e50;
            color: white;
            padding: 20px;
            z-index: 10000;
            font-family: Arial, sans-serif;
            font-size: 14px;
            box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
        `;
        
        banner.innerHTML = `
            <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;">
                <div style="flex: 1; margin-right: 20px;">
                    <p style="margin: 0;">This website uses cookies to enhance your experience and analyze traffic. By continuing to use this site, you consent to our use of cookies.</p>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button id="cb-accept" style="background: #27ae60; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">Accept</button>
                    <button id="cb-decline" style="background: #e74c3c; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer;">Decline</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(banner);
        
        // Track banner shown
        trackEvent('banner_shown');
        
        // Handle consent
        document.getElementById('cb-accept').onclick = function() {
            localStorage.setItem('cb_consent_given', 'true');
            trackEvent('consent_given', { consent_given: true });
            banner.remove();
        };
        
        document.getElementById('cb-decline').onclick = function() {
            localStorage.setItem('cb_consent_given', 'false');
            trackEvent('consent_denied', { consent_given: false });
            banner.remove();
        };
    }
    
    // Show banner when page loads
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', showCookieBanner);
    } else {
        showCookieBanner();
    }
    
    // Expose API
    window.CookieBot = {
        track: trackEvent,
        getVisitorId: generateVisitorId,
        config: config
    };
    
})();
    """.strip()
    
    response = jsonify(script_content)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Cache-Control'] = 'public, max-age=3600'  # Cache for 1 hour
    
    return response


@public_bp.route('/status/<client_id>', methods=['GET'])
@limiter.limit("100 per hour")
def get_website_status(client_id: str):
    """Get website status for client-side validation."""
    try:
        website = Website.query.filter_by(client_id=client_id).first()
        
        if not website:
            return APIResponse.error(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                status_code=404
            )
        
        return APIResponse.success({
            'status': website.status,
            'domain': website.domain,
            'tracking_enabled': website.status == 'active'
        })
        
    except Exception as e:
        logger.error("Failed to get website status", client_id=client_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to get website status",
            500
        )


@public_bp.route('/privacy-policy', methods=['GET'])
def get_privacy_policy():
    """Serve privacy policy for compliance."""
    privacy_policy = {
        'title': 'CookieBot.ai Privacy Policy',
        'last_updated': '2024-01-01',
        'sections': [
            {
                'title': 'Information We Collect',
                'content': 'We collect information about your website visitors to provide analytics and compliance services.'
            },
            {
                'title': 'How We Use Information',
                'content': 'We use collected information to provide analytics insights and ensure GDPR compliance.'
            },
            {
                'title': 'Data Retention',
                'content': 'We retain analytics data for up to 2 years to provide historical insights.'
            },
            {
                'title': 'Your Rights',
                'content': 'You have the right to access, modify, or delete your data at any time.'
            }
        ]
    }
    
    return APIResponse.success(privacy_policy)


@public_bp.route('/batch-track', methods=['POST'])
@limiter.limit("100 per hour")
def batch_track_events():
    """
    Track multiple events in a single request for performance.
    """
    try:
        data = request.get_json() or {}
        events = data.get('events', [])
        
        if not events or len(events) > 50:  # Limit batch size
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Invalid batch size. Must be between 1 and 50 events.",
                400
            )
        
        processed_events = []
        
        for event_data in events:
            try:
                # Validate each event
                schema = AnalyticsEventSchema()
                validated_event = schema.load(event_data)
                
                client_id = validated_event['client_id']
                
                # Find website
                website = Website.query.filter_by(client_id=client_id).first()
                if not website or website.status != 'active':
                    continue  # Skip invalid events
                
                # Create event
                event = AnalyticsEvent.create_event(
                    website_id=website.id,
                    event_type=validated_event['event_type'],
                    visitor_id=validated_event.get('visitor_id'),
                    consent_given=validated_event.get('consent_given'),
                    revenue_generated=validated_event.get('revenue_generated', 0),
                    metadata=validated_event.get('metadata', {})
                )
                
                processed_events.append(event.id)
                
            except Exception as e:
                logger.warning("Failed to process batch event", event_data=event_data, error=str(e))
                continue
        
        return APIResponse.success({
            'processed_count': len(processed_events),
            'event_ids': processed_events
        }, f"Processed {len(processed_events)} events")
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to process batch events", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to process batch events",
            500
        )

