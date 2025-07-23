"""
Compliance scanning models for CookieBot.ai application.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
import json


class ComplianceScan:
    """Model for compliance scan records"""
    
    def __init__(self, db_connection):
        self.db = db_connection
    
    @classmethod
    def create_table(cls, db_connection):
        """Create compliance_scans table if it doesn't exist"""
        try:
            cur = db_connection.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS compliance_scans (
                    id SERIAL PRIMARY KEY,
                    website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                    scan_type VARCHAR(100) NOT NULL,
                    status VARCHAR(50) DEFAULT 'pending',
                    results JSONB,
                    recommendations TEXT,
                    compliance_score INTEGER DEFAULT 0,
                    cookies_found INTEGER DEFAULT 0,
                    scripts_found INTEGER DEFAULT 0,
                    scan_url TEXT,
                    scan_duration INTEGER,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    INDEX(website_id),
                    INDEX(status),
                    INDEX(created_at)
                )
            ''')
            db_connection.commit()
            return True
        except Exception as e:
            print(f"Error creating compliance_scans table: {e}")
            db_connection.rollback()
            return False
    
    def create_scan(self, website_id: int, scan_type: str, scan_url: str) -> Optional[int]:
        """Create a new compliance scan"""
        try:
            cur = self.db.cursor()
            cur.execute("""
                INSERT INTO compliance_scans (website_id, scan_type, scan_url, status)
                VALUES (%s, %s, %s, 'pending')
                RETURNING id
            """, (website_id, scan_type, scan_url))
            
            scan_id = cur.fetchone()['id']
            self.db.commit()
            return scan_id
        except Exception as e:
            print(f"Error creating compliance scan: {e}")
            self.db.rollback()
            return None
    
    def update_scan_results(self, scan_id: int, results: Dict[str, Any], 
                          compliance_score: int, recommendations: str) -> bool:
        """Update scan with results"""
        try:
            cur = self.db.cursor()
            cur.execute("""
                UPDATE compliance_scans 
                SET results = %s, compliance_score = %s, recommendations = %s,
                    status = 'completed', completed_at = CURRENT_TIMESTAMP,
                    cookies_found = %s, scripts_found = %s
                WHERE id = %s
            """, (
                json.dumps(results),
                compliance_score,
                recommendations,
                len(results.get('cookies', [])),
                len(results.get('scripts', [])),
                scan_id
            ))
            
            self.db.commit()
            return True
        except Exception as e:
            print(f"Error updating scan results: {e}")
            self.db.rollback()
            return False
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get scan by ID"""
        try:
            cur = self.db.cursor()
            cur.execute("""
                SELECT * FROM compliance_scans WHERE id = %s
            """, (scan_id,))
            
            return cur.fetchone()
        except Exception as e:
            print(f"Error getting scan: {e}")
            return None
    
    def get_website_scans(self, website_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans for a website"""
        try:
            cur = self.db.cursor()
            cur.execute("""
                SELECT * FROM compliance_scans 
                WHERE website_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (website_id, limit))
            
            return cur.fetchall()
        except Exception as e:
            print(f"Error getting website scans: {e}")
            return []


class CookieCategory:
    """Model for cookie categories"""
    
    NECESSARY = 'necessary'
    FUNCTIONAL = 'functional'
    STATISTICS = 'statistics'
    MARKETING = 'marketing'
    
    CATEGORIES = [NECESSARY, FUNCTIONAL, STATISTICS, MARKETING]
    
    @classmethod
    def get_category_info(cls, category: str) -> Dict[str, str]:
        """Get category information"""
        category_info = {
            cls.NECESSARY: {
                'name': 'Strictly Necessary',
                'description': 'Essential for website functionality',
                'color': '#28a745',
                'consent_required': False
            },
            cls.FUNCTIONAL: {
                'name': 'Functional',
                'description': 'Enable enhanced functionality and personalization',
                'color': '#17a2b8',
                'consent_required': True
            },
            cls.STATISTICS: {
                'name': 'Statistics',
                'description': 'Help understand how visitors interact with the website',
                'color': '#ffc107',
                'consent_required': True
            },
            cls.MARKETING: {
                'name': 'Marketing',
                'description': 'Used to track visitors and display relevant ads',
                'color': '#dc3545',
                'consent_required': True
            }
        }
        
        return category_info.get(category, {
            'name': 'Unknown',
            'description': 'Unknown category',
            'color': '#6c757d',
            'consent_required': True
        })


class TrackingService:
    """Model for tracking service detection"""
    
    SERVICES = {
        'google-analytics': {
            'patterns': [r'google-analytics\.com', r'googletagmanager\.com', r'gtag\(', r'ga\('],
            'name': 'Google Analytics',
            'category': 'statistics',
            'privacy_policy': 'https://policies.google.com/privacy'
        },
        'facebook-pixel': {
            'patterns': [r'facebook\.net.*fbevents', r'fbq\('],
            'name': 'Facebook Pixel',
            'category': 'marketing',
            'privacy_policy': 'https://www.facebook.com/privacy/explanation'
        },
        'google-ads': {
            'patterns': [r'googleadservices\.com', r'googlesyndication\.com'],
            'name': 'Google Ads',
            'category': 'marketing',
            'privacy_policy': 'https://policies.google.com/privacy'
        },
        'hotjar': {
            'patterns': [r'hotjar\.com'],
            'name': 'Hotjar',
            'category': 'statistics',
            'privacy_policy': 'https://www.hotjar.com/legal/policies/privacy/'
        },
        'mixpanel': {
            'patterns': [r'mixpanel\.com'],
            'name': 'Mixpanel',
            'category': 'statistics',
            'privacy_policy': 'https://mixpanel.com/legal/privacy-policy/'
        },
        'intercom': {
            'patterns': [r'intercom\.io', r'widget\.intercom\.io'],
            'name': 'Intercom',
            'category': 'functional',
            'privacy_policy': 'https://www.intercom.com/legal/privacy'
        },
        'zendesk': {
            'patterns': [r'zendesk\.com', r'zdassets\.com'],
            'name': 'Zendesk',
            'category': 'functional',
            'privacy_policy': 'https://www.zendesk.com/company/privacy-and-data-protection/'
        },
        'hubspot': {
            'patterns': [r'hubspot\.com', r'hs-scripts\.com'],
            'name': 'HubSpot',
            'category': 'marketing',
            'privacy_policy': 'https://legal.hubspot.com/privacy-policy'
        },
        'mailchimp': {
            'patterns': [r'mailchimp\.com', r'list-manage\.com'],
            'name': 'Mailchimp',
            'category': 'marketing',
            'privacy_policy': 'https://mailchimp.com/legal/privacy/'
        },
        'stripe': {
            'patterns': [r'stripe\.com', r'js\.stripe\.com'],
            'name': 'Stripe',
            'category': 'functional',
            'privacy_policy': 'https://stripe.com/privacy'
        },
        'paypal': {
            'patterns': [r'paypal\.com', r'paypalobjects\.com'],
            'name': 'PayPal',
            'category': 'functional',
            'privacy_policy': 'https://www.paypal.com/privacy'
        },
        'youtube': {
            'patterns': [r'youtube\.com', r'ytimg\.com'],
            'name': 'YouTube',
            'category': 'marketing',
            'privacy_policy': 'https://policies.google.com/privacy'
        },
        'twitter': {
            'patterns': [r'twitter\.com', r'twimg\.com'],
            'name': 'Twitter',
            'category': 'marketing',
            'privacy_policy': 'https://twitter.com/privacy'
        },
        'linkedin': {
            'patterns': [r'linkedin\.com', r'licdn\.com'],
            'name': 'LinkedIn',
            'category': 'marketing',
            'privacy_policy': 'https://www.linkedin.com/legal/privacy-policy'
        },
        'tiktok': {
            'patterns': [r'tiktok\.com', r'bytedance\.com'],
            'name': 'TikTok',
            'category': 'marketing',
            'privacy_policy': 'https://www.tiktok.com/legal/privacy-policy'
        }
    }
    
    @classmethod
    def get_service_info(cls, service_id: str) -> Dict[str, Any]:
        """Get service information by ID"""
        return cls.SERVICES.get(service_id, {
            'name': 'Unknown Service',
            'category': 'unknown',
            'privacy_policy': None
        })
    
    @classmethod
    def get_all_services(cls) -> Dict[str, Dict[str, Any]]:
        """Get all tracking services"""
        return cls.SERVICES
