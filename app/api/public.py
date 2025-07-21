"""
Public API endpoints for website tracking and integration.
Enhanced with auto-registration and improved tracking capabilities.
"""
from datetime import datetime
from typing import Dict, Any

from flask import Blueprint, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from app.models.user import User
from app.models.website import Website
from app.models.analytics import AnalyticsEvent
from app.utils.database import db
from app.utils.error_handlers import APIResponse, APIException, ErrorCodes
from app.utils.validators import validate_json, AnalyticsEventSchema

logger = structlog.get_logger()

# Create blueprint
public_bp = Blueprint('public', __name__)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)


@public_bp.route('/register-website', methods=['POST'])
@limiter.limit("10 per minute")
def register_website():
    """
    Auto-register website when tracking script is first loaded.
    This enables the auto-population feature for the websites dashboard.
    """
    try:
        data = request.get_json()
        
        if not data:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "JSON data required",
                400
            )
        
        # Validate required fields
        api_key = data.get('api_key')
        domain = data.get('domain')
        referrer = data.get('referrer', '')
        
        if not api_key:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "API key is required",
                400
            )
        
        if not domain:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Domain is required",
                400
            )
        
        # Authenticate user via API key
        user = User.get_user_by_api_key(api_key)
        if not user:
            raise APIException(
                ErrorCodes.AUTHENTICATION_FAILED,
                "Invalid API key",
                401
            )
        
        # Clean and validate domain
        clean_domain = domain.lower().strip()
        if clean_domain.startswith('http://'):
            clean_domain = clean_domain[7:]
        elif clean_domain.startswith('https://'):
            clean_domain = clean_domain[8:]
        
        # Remove www prefix and trailing slash
        if clean_domain.startswith('www.'):
            clean_domain = clean_domain[4:]
        clean_domain = clean_domain.rstrip('/')
        
        # Basic domain validation
        if not clean_domain or len(clean_domain) < 3:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Invalid domain format",
                400
            )
        
        # Check if website already exists for this user
        existing_website = Website.query.filter_by(
            user_id=user.id,
            domain=clean_domain
        ).first()
        
        if existing_website:
            # Return existing website info
            logger.info(
                "Website already registered",
                user_id=user.id,
                domain=clean_domain,
                website_id=existing_website.id
            )
            
            return APIResponse.success({
                'website_id': existing_website.id,
                'client_id': existing_website.client_id,
                'domain': existing_website.domain,
                'status': existing_website.status,
                'message': 'Website already registered'
            })
        
        # Create new website
        website = Website(
            user_id=user.id,
            domain=clean_domain,
            status='pending'
        )
        
        # Generate integration code
        website.generate_integration_code()
        
        db.session.add(website)
        db.session.commit()
        
        logger.info(
            "Website auto-registered",
            user_id=user.id,
            website_id=website.id,
            domain=clean_domain,
            client_id=website.client_id,
            referrer=referrer
        )
        
        return APIResponse.success({
            'website_id': website.id,
            'client_id': website.client_id,
            'domain': website.domain,
            'status': website.status,
            'message': 'Website registered successfully'
        }, status_code=201)
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to register website",
            api_key=data.get('api_key', 'unknown')[:10] + '...' if data and data.get('api_key') else 'none',
            domain=data.get('domain', 'unknown') if data else 'none',
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to register website",
            500
        )


@public_bp.route('/track', methods=['POST'])
@limiter.limit("1000 per hour")
@validate_json(AnalyticsEventSchema)
def track_event(validated_data: Dict[str, Any]):
    """
    Track analytics events from websites.
    Enhanced with better error handling and revenue tracking.
    """
    try:
        client_id = validated_data['client_id']
        event_type = validated_data['event_type']
        visitor_id = validated_data.get('visitor_id')
        consent_given = validated_data.get('consent_given')
        metadata = validated_data.get('metadata', {})
        
        # Find website by client ID
        website = Website.query.filter_by(client_id=client_id).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Create analytics event
        event = AnalyticsEvent(
            website_id=website.id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            metadata=metadata,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        db.session.add(event)
        
        # Update website metrics
        if event_type == 'page_view':
            website.visitors_today += 1
        
        # Calculate revenue for consent events
        revenue_generated = 0.0
        if event_type in ['consent_given', 'consent_denied'] and consent_given:
            # Base revenue per consent (can be configured)
            base_revenue = 0.05  # $0.05 per consent
            revenue_generated = base_revenue
            
            event.revenue_generated = revenue_generated
            website.revenue_today += revenue_generated
            
            # Add revenue to user account (70% share)
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
    This script is loaded by websites to enable tracking and auto-registration.
    """
    script_content = """
(function() {
    'use strict';
    
    var CookieBot = window.CookieBot || {};
    
    // Configuration
    var config = {
        apiUrl: CookieBot.apiUrl || 'https://cookiebot-ai-backend-production.up.railway.app/api/public',
        clientId: CookieBot.clientId,
        apiKey: CookieBot.apiKey,
        debug: false
    };
    
    // Auto-register website if API key is available (handled by integration code)
    // This script focuses on tracking and cookie consent functionality
    
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
                timestamp: new Date().toISOString(),
                user_agent: navigator.userAgent,
                referrer: document.referrer
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
    
    // Enhanced cookie banner functionality
    function showCookieBanner() {
        // Check if user already responded
        var consentGiven = localStorage.getItem('cb_consent_given');
        if (consentGiven !== null) {
            // Track existing consent status
            trackEvent('consent_status', { 
                consent_given: consentGiven === 'true',
                existing_consent: true 
            });
            return;
        }
        
        var banner = document.createElement('div');
        banner.id = 'cookiebot-banner';
        banner.style.cssText = `
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            z-index: 10000;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            box-shadow: 0 -4px 20px rgba(0,0,0,0.15);
            backdrop-filter: blur(10px);
            border-top: 1px solid rgba(255,255,255,0.1);
        `;
        
        banner.innerHTML = `
            <div style="max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 300px;">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        <span style="font-size: 18px; margin-right: 8px;">🍪</span>
                        <strong style="font-size: 16px;">Cookie Consent</strong>
                    </div>
                    <p style="margin: 0; opacity: 0.9; line-height: 1.4;">
                        We use cookies to enhance your experience, analyze traffic, and personalize content. 
                        Your privacy matters to us.
                    </p>
                </div>
                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <button id="cb-accept" style="
                        background: #27ae60; 
                        color: white; 
                        border: none; 
                        padding: 12px 24px; 
                        border-radius: 6px; 
                        cursor: pointer; 
                        font-weight: 600;
                        transition: all 0.3s ease;
                        box-shadow: 0 2px 8px rgba(39, 174, 96, 0.3);
                    ">Accept All</button>
                    <button id="cb-decline" style="
                        background: transparent; 
                        color: white; 
                        border: 2px solid rgba(255,255,255,0.3); 
                        padding: 10px 20px; 
                        border-radius: 6px; 
                        cursor: pointer;
                        font-weight: 600;
                        transition: all 0.3s ease;
                    ">Decline</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(banner);
        
        // Add hover effects
        var acceptBtn = document.getElementById('cb-accept');
        var declineBtn = document.getElementById('cb-decline');
        
        acceptBtn.onmouseover = function() {
            this.style.background = '#229954';
            this.style.transform = 'translateY(-1px)';
        };
        acceptBtn.onmouseout = function() {
            this.style.background = '#27ae60';
            this.style.transform = 'translateY(0)';
        };
        
        declineBtn.onmouseover = function() {
            this.style.background = 'rgba(255,255,255,0.1)';
            this.style.borderColor = 'rgba(255,255,255,0.5)';
        };
        declineBtn.onmouseout = function() {
            this.style.background = 'transparent';
            this.style.borderColor = 'rgba(255,255,255,0.3)';
        };
        
        // Track banner shown
        trackEvent('banner_shown');
        
        // Handle consent
        acceptBtn.onclick = function() {
            localStorage.setItem('cb_consent_given', 'true');
            trackEvent('consent_given', { consent_given: true });
            banner.style.transform = 'translateY(100%)';
            banner.style.transition = 'transform 0.3s ease';
            setTimeout(function() { banner.remove(); }, 300);
        };
        
        declineBtn.onclick = function() {
            localStorage.setItem('cb_consent_given', 'false');
            trackEvent('consent_denied', { consent_given: false });
            banner.style.transform = 'translateY(100%)';
            banner.style.transition = 'transform 0.3s ease';
            setTimeout(function() { banner.remove(); }, 300);
        };
    }
    
    // Initialize tracking
    function initialize() {
        // Auto-track page view
        trackEvent('page_view');
        
        // Show cookie banner
        showCookieBanner();
        
        // Track session start
        if (!sessionStorage.getItem('cb_session_started')) {
            sessionStorage.setItem('cb_session_started', 'true');
            trackEvent('session_start');
        }
        
        // Track page unload
        window.addEventListener('beforeunload', function() {
            trackEvent('page_unload');
        });
        
        // Track scroll depth
        var maxScroll = 0;
        window.addEventListener('scroll', function() {
            var scrollPercent = Math.round((window.scrollY / (document.body.scrollHeight - window.innerHeight)) * 100);
            if (scrollPercent > maxScroll && scrollPercent % 25 === 0) {
                maxScroll = scrollPercent;
                trackEvent('scroll_depth', { scroll_percent: scrollPercent });
            }
        });
    }
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
    
    // Expose enhanced API
    window.CookieBot = Object.assign(CookieBot, {
        track: trackEvent,
        getVisitorId: generateVisitorId,
        config: config,
        showBanner: showCookieBanner,
        getConsentStatus: function() {
            var consent = localStorage.getItem('cb_consent_given');
            return consent === null ? null : consent === 'true';
        },
        resetConsent: function() {
            localStorage.removeItem('cb_consent_given');
            showCookieBanner();
        }
    });
    
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

