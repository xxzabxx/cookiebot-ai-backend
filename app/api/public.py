"""
Public API endpoints for website tracking and integration.
Enhanced with auto-registration, improved tracking capabilities, and unified API key support.
Maintains full backward compatibility while adding new unified features.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

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


# PRESERVED: Original auto-registration endpoint
@public_bp.route('/register-website', methods=['POST'])
@limiter.limit("10 per minute")
def register_website():
    """
    Auto-register website when tracking script is first loaded.
    Enhanced with unified API key support while maintaining backward compatibility.
    """
    try:
        data = request.get_json()
        
        if not data:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "JSON data required",
                400
            )
        
        # ENHANCED: Support both legacy client_id and new unified API key approaches
        api_key = data.get('api_key')
        client_id = data.get('client_id')  # Legacy support
        domain = data.get('domain')
        referrer = data.get('referrer', '')
        
        # Determine authentication method
        user = None
        if api_key:
            # NEW: Unified API key approach
            user = User.get_user_by_api_key(api_key)
            if not user:
                raise APIException(
                    ErrorCodes.AUTHENTICATION_FAILED,
                    "Invalid API key",
                    401
                )
        elif client_id:
            # PRESERVED: Legacy client_id approach
            existing_website = Website.query.filter_by(client_id=client_id).first()
            if existing_website:
                user = existing_website.user
            else:
                raise APIException(
                    ErrorCodes.AUTHENTICATION_FAILED,
                    "Invalid client ID",
                    401
                )
        else:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Either API key or client ID is required",
                400
            )
        
        if not domain:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Domain is required",
                400
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
                website_id=existing_website.id,
                approach='unified' if api_key else 'legacy'
            )
            
            return APIResponse.success({
                'website_id': existing_website.id,
                'client_id': existing_website.client_id,
                'domain': existing_website.domain,
                'status': existing_website.status,
                'message': 'Website already registered',
                'approach': 'unified' if api_key else 'legacy'
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
            referrer=referrer,
            approach='unified' if api_key else 'legacy'
        )
        
        return APIResponse.success({
            'website_id': website.id,
            'client_id': website.client_id,
            'domain': website.domain,
            'status': website.status,
            'message': 'Website registered successfully',
            'approach': 'unified' if api_key else 'legacy'
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


# PRESERVED: Original tracking endpoint with enhancements
@public_bp.route('/track', methods=['POST'])
@limiter.limit("1000 per hour")
def track_event():
    """
    Track analytics events from websites.
    Enhanced with unified API key support and better error handling.
    """
    try:
        data = request.get_json()
        
        if not data:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "JSON data required",
                400
            )
        
        # ENHANCED: Support both legacy and unified approaches
        api_key = data.get('api_key')
        client_id = data.get('client_id')
        domain = data.get('domain')  # NEW: For unified approach
        event_type = data.get('event_type')
        visitor_id = data.get('visitor_id')
        consent_given = data.get('consent_given')
        metadata = data.get('metadata', {})
        revenue_generated = data.get('revenue_generated', 0.0)
        
        if not event_type:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Event type is required",
                400
            )
        
        website = None
        user = None
        approach = 'legacy'
        
        if api_key and domain:
            # NEW: Unified API key approach
            approach = 'unified'
            user = User.get_user_by_api_key(api_key)
            if not user:
                raise APIException(
                    ErrorCodes.AUTHENTICATION_FAILED,
                    "Invalid API key",
                    401
                )
            
            # Clean domain
            clean_domain = domain.lower().strip()
            if clean_domain.startswith('http://'):
                clean_domain = clean_domain[7:]
            elif clean_domain.startswith('https://'):
                clean_domain = clean_domain[8:]
            if clean_domain.startswith('www.'):
                clean_domain = clean_domain[4:]
            clean_domain = clean_domain.rstrip('/')
            
            # Find or create website for unified approach
            website = Website.query.filter_by(
                user_id=user.id,
                domain=clean_domain
            ).first()
            
            if not website:
                # Auto-create website for unified approach
                website = Website(
                    user_id=user.id,
                    domain=clean_domain,
                    status='active'  # Auto-activate for unified approach
                )
                website.generate_integration_code()
                db.session.add(website)
                db.session.flush()  # Get the ID
                
                logger.info(
                    "Website auto-created for unified tracking",
                    user_id=user.id,
                    domain=clean_domain,
                    website_id=website.id
                )
            
        elif client_id:
            # PRESERVED: Legacy client_id approach
            website = Website.query.filter_by(client_id=client_id).first()
            if not website:
                raise APIException(
                    ErrorCodes.RESOURCE_NOT_FOUND,
                    "Website not found",
                    404
                )
            user = website.user
            
        else:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Either (api_key + domain) or client_id is required",
                400
            )
        
        # Create analytics event with enhanced data
        event = AnalyticsEvent.create_event(
            website_id=website.id,
            event_type=event_type,
            visitor_id=visitor_id,
            consent_given=consent_given,
            revenue_generated=revenue_generated,
            metadata=metadata,
            # NEW: Unified fields
            api_key=api_key if approach == 'unified' else None,
            domain=domain if approach == 'unified' else website.domain,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        # Update website metrics
        if event_type == 'page_view':
            website.visitors_today = (website.visitors_today or 0) + 1
        
        # Enhanced revenue calculation
        if event_type in ['consent_given', 'consent_denied'] and consent_given:
            if revenue_generated == 0.0:
                # Default revenue calculation
                base_revenue = 0.05  # $0.05 per consent
                revenue_generated = base_revenue
                event.revenue_generated = revenue_generated
            
            website.revenue_today = (website.revenue_today or 0) + revenue_generated
            
            # Add revenue to user account (70% share)
            revenue_share = 0.7  # 70% to user, 30% to platform
            user_revenue = revenue_generated * revenue_share
            if hasattr(user, 'add_revenue'):
                user.add_revenue(user_revenue, f"Revenue from {website.domain}")
        
        website.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(
            "Event tracked successfully",
            event_id=event.id,
            website_id=website.id,
            event_type=event_type,
            approach=approach,
            revenue=revenue_generated
        )
        
        return APIResponse.success({
            'event_id': event.id,
            'status': 'tracked',
            'approach': approach,
            'website_id': website.id
        }, "Event tracked successfully")
        
    except APIException:
        raise
    except Exception as e:
        logger.error(
            "Failed to track event",
            data=data,
            error=str(e)
        )
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to track event",
            500
        )


# PRESERVED: Original script serving endpoint
@public_bp.route('/script.js', methods=['GET'])
def get_tracking_script():
    """
    Serve the JavaScript tracking script.
    Enhanced with unified API key support while maintaining backward compatibility.
    """
    script_content = """
(function() {
    'use strict';
    
    var CookieBot = window.CookieBot || {};
    
    // Enhanced configuration with unified support
    var config = {
        apiUrl: CookieBot.apiUrl || 'https://cookiebot-ai-backend-production.up.railway.app/api/public',
        clientId: CookieBot.clientId,  // Legacy support
        apiKey: CookieBot.apiKey,      // NEW: Unified approach
        debug: CookieBot.debug || false,
        approach: CookieBot.apiKey ? 'unified' : 'legacy'
    };
    
    // Auto-register website for unified approach
    if (config.apiKey && config.approach === 'unified') {
        fetch(config.apiUrl + '/register-website', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                api_key: config.apiKey,
                domain: window.location.hostname,
                referrer: document.referrer || window.location.href
            })
        }).then(function(response) {
            return response.json();
        }).then(function(data) {
            if (data.success) {
                config.clientId = data.data.client_id;
                config.websiteId = data.data.website_id;
                if (config.debug) {
                    console.log('CookieBot: Website auto-registered (unified)', data.data);
                }
            }
        }).catch(function(error) {
            if (config.debug) {
                console.warn('CookieBot auto-registration failed:', error);
            }
        });
    }
    
    // Utility functions
    function generateVisitorId() {
        var stored = localStorage.getItem('cb_visitor_id');
        if (stored) return stored;
        
        var id = 'cb_' + Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
        localStorage.setItem('cb_visitor_id', id);
        return id;
    }
    
    function trackEvent(eventType, data) {
        var payload = {
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
        
        // Enhanced: Support both approaches
        if (config.approach === 'unified' && config.apiKey) {
            payload.api_key = config.apiKey;
            payload.domain = window.location.hostname;
        } else if (config.clientId) {
            payload.client_id = config.clientId;
        } else {
            if (config.debug) {
                console.warn('CookieBot: No valid authentication configured');
            }
            return;
        }
        
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
        }).then(function(response) {
            if (config.debug && response.ok) {
                console.log('CookieBot: Event tracked -', eventType);
            }
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
        if (CookieBot.config && CookieBot.config.autoShow !== false) {
            showCookieBanner();
        }
        
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
    
    // Enhanced API exposure
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
        },
        // NEW: Unified approach helpers
        isUnified: function() {
            return config.approach === 'unified';
        },
        getApproach: function() {
            return config.approach;
        }
    });
    
})();
    """.strip()
    
    response = jsonify(script_content)
    response.headers['Content-Type'] = 'application/javascript'
    response.headers['Cache-Control'] = 'public, max-age=3600'  # Cache for 1 hour
    
    return response


# PRESERVED: Original status endpoint with enhancements
@public_bp.route('/status/<identifier>', methods=['GET'])
@limiter.limit("100 per hour")
def get_website_status(identifier: str):
    """
    Get website status for client-side validation.
    Enhanced to support both client_id and API key identification.
    """
    try:
        website = None
        approach = 'legacy'
        
        # Try to find by client_id first (legacy)
        website = Website.query.filter_by(client_id=identifier).first()
        
        if not website:
            # Try to find by API key (unified approach)
            user = User.get_user_by_api_key(identifier)
            if user:
                approach = 'unified'
                # For unified approach, return aggregate status
                websites = Website.query.filter_by(user_id=user.id).all()
                if websites:
                    active_count = sum(1 for w in websites if w.status == 'active')
                    return APIResponse.success({
                        'approach': 'unified',
                        'total_websites': len(websites),
                        'active_websites': active_count,
                        'tracking_enabled': active_count > 0,
                        'user_id': user.id
                    })
        
        if not website:
            return APIResponse.error(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                status_code=404
            )
        
        return APIResponse.success({
            'approach': approach,
            'status': website.status,
            'domain': website.domain,
            'tracking_enabled': website.status == 'active',
            'website_id': website.id
        })
        
    except Exception as e:
        logger.error("Failed to get website status", identifier=identifier, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to get website status",
            500
        )


# PRESERVED: Privacy policy endpoint
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


# PRESERVED: Batch tracking endpoint with enhancements
@public_bp.route('/batch-track', methods=['POST'])
@limiter.limit("100 per hour")
def batch_track_events():
    """
    Track multiple events in a single request for performance.
    Enhanced with unified API key support.
    """
    try:
        data = request.get_json() or {}
        events = data.get('events', [])
        api_key = data.get('api_key')  # NEW: Unified approach
        
        if not events or len(events) > 50:  # Limit batch size
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Invalid batch size. Must be between 1 and 50 events.",
                400
            )
        
        processed_events = []
        user = None
        approach = 'legacy'
        
        # NEW: Unified API key authentication
        if api_key:
            approach = 'unified'
            user = User.get_user_by_api_key(api_key)
            if not user:
                raise APIException(
                    ErrorCodes.AUTHENTICATION_FAILED,
                    "Invalid API key",
                    401
                )
        
        for event_data in events:
            try:
                website = None
                
                if approach == 'unified':
                    # NEW: Unified approach
                    domain = event_data.get('domain')
                    if not domain:
                        continue
                    
                    # Clean domain
                    clean_domain = domain.lower().strip()
                    if clean_domain.startswith('http://'):
                        clean_domain = clean_domain[7:]
                    elif clean_domain.startswith('https://'):
                        clean_domain = clean_domain[8:]
                    if clean_domain.startswith('www.'):
                        clean_domain = clean_domain[4:]
                    clean_domain = clean_domain.rstrip('/')
                    
                    # Find or create website
                    website = Website.query.filter_by(
                        user_id=user.id,
                        domain=clean_domain
                    ).first()
                    
                    if not website:
                        website = Website(
                            user_id=user.id,
                            domain=clean_domain,
                            status='active'
                        )
                        website.generate_integration_code()
                        db.session.add(website)
                        db.session.flush()
                else:
                    # PRESERVED: Legacy approach
                    client_id = event_data.get('client_id')
                    if not client_id:
                        continue
                    
                    website = Website.query.filter_by(client_id=client_id).first()
                    if not website or website.status != 'active':
                        continue
                
                if not website:
                    continue
                
                # Create event
                event = AnalyticsEvent.create_event(
                    website_id=website.id,
                    event_type=event_data.get('event_type', 'unknown'),
                    visitor_id=event_data.get('visitor_id'),
                    consent_given=event_data.get('consent_given'),
                    revenue_generated=event_data.get('revenue_generated', 0),
                    metadata=event_data.get('metadata', {}),
                    # NEW: Unified fields
                    api_key=api_key if approach == 'unified' else None,
                    domain=event_data.get('domain') if approach == 'unified' else website.domain,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent', '')
                )
                
                processed_events.append(event.id)
                
            except Exception as e:
                logger.warning("Failed to process batch event", event_data=event_data, error=str(e))
                continue
        
        return APIResponse.success({
            'processed_count': len(processed_events),
            'event_ids': processed_events,
            'approach': approach
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


# NEW: Unified dashboard summary endpoint
@public_bp.route('/dashboard-summary', methods=['POST'])
@limiter.limit("100 per hour")
def get_unified_dashboard_summary():
    """
    Get dashboard summary using unified API key approach.
    Provides cross-website analytics for a user.
    """
    try:
        data = request.get_json() or {}
        api_key = data.get('api_key')
        days = data.get('days', 30)
        
        if not api_key:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "API key is required",
                400
            )
        
        # Authenticate user
        user = User.get_user_by_api_key(api_key)
        if not user:
            raise APIException(
                ErrorCodes.AUTHENTICATION_FAILED,
                "Invalid API key",
                401
            )
        
        # Get unified analytics
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        analytics = AnalyticsEvent.get_unified_analytics(
            api_key=api_key,
            start_date=start_date,
            end_date=end_date
        )
        
        # Get website breakdown
        website_breakdown = AnalyticsEvent.get_unified_website_breakdown(
            api_key=api_key,
            start_date=start_date,
            end_date=end_date
        )
        
        # Get recent activity
        recent_events = AnalyticsEvent.query.filter(
            AnalyticsEvent.api_key == api_key,
            AnalyticsEvent.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(
            AnalyticsEvent.created_at.desc()
        ).limit(10).all()
        
        recent_activity = [
            {
                'event_type': event.event_type,
                'website_domain': event.domain,
                'created_at': event.created_at.isoformat(),
                'consent_given': event.consent_given,
                'revenue_generated': float(event.revenue_generated or 0)
            }
            for event in recent_events
        ]
        
        return APIResponse.success({
            'approach': 'unified',
            'total_websites': analytics['total_websites'],
            'total_visitors_today': analytics['unique_visitors'],
            'total_revenue_today': analytics['total_revenue'],
            'average_consent_rate': analytics['consent_rate'],
            'website_breakdown': website_breakdown,
            'recent_activity': recent_activity,
            'period_days': days
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get unified dashboard summary", api_key=api_key[:10] + '...' if api_key else 'none', error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to get dashboard summary",
            500
        )


# NEW: Health check endpoint
@public_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    try:
        # Basic database connectivity check
        db.session.execute('SELECT 1')
        
        return APIResponse.success({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'features': {
                'unified_api_key': True,
                'legacy_client_id': True,
                'auto_registration': True,
                'batch_tracking': True
            }
        })
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return APIResponse.error(
            ErrorCodes.INTERNAL_ERROR,
            "Service unhealthy",
            status_code=503
        )

