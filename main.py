from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from datetime import datetime, timedelta
import uuid
import json
import logging
import requests
from bs4 import BeautifulSoup
import re
import threading
import time
from urllib.parse import urlparse, urljoin
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
jwt = JWTManager(app)

# CORS Configuration - Fixed for Vercel deployment
CORS(app, 
     origins=['https://cookiebot.ai', 'https://www.cookiebot.ai', 'http://localhost:3000'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
     supports_credentials=True)

# Global storage for active scans
active_scans = {}

# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(
            os.environ.get('DATABASE_URL'),
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

# Initialize database tables
def init_db():
    conn = get_db_connection()
    if not conn:
        logger.error("Failed to connect to database")
        return False
    
    try:
        cur = conn.cursor()
        
        # Users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                company VARCHAR(255),
                subscription_tier VARCHAR(50) DEFAULT 'free',
                revenue_balance DECIMAL(10,2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Websites table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                domain VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                visitors_today INTEGER DEFAULT 0,
                consent_rate DECIMAL(5,2) DEFAULT 0.00,
                revenue_today DECIMAL(10,2) DEFAULT 0.00,
                integration_code TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, domain)
            )
        ''')
        
        # Analytics events table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                visitor_id VARCHAR(255),
                consent_given BOOLEAN,
                revenue_generated DECIMAL(10,2) DEFAULT 0.00,
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance scans table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS compliance_scans (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                scan_type VARCHAR(100) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                results JSONB,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        logger.info("Database tables initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

# Initialize database on startup
init_db()

# Real Website Analyzer Class
class RealWebsiteAnalyzer:
    def __init__(self):
        self.tracking_services = {
            'google-analytics': {
                'patterns': [r'google-analytics\.com', r'googletagmanager\.com', r'gtag\(', r'ga\('],
                'name': 'Google Analytics',
                'category': 'statistics'
            },
            'facebook-pixel': {
                'patterns': [r'facebook\.net.*fbevents', r'fbq\('],
                'name': 'Facebook Pixel',
                'category': 'marketing'
            },
            'google-ads': {
                'patterns': [r'googleadservices\.com', r'googlesyndication\.com'],
                'name': 'Google Ads',
                'category': 'marketing'
            },
            'hotjar': {
                'patterns': [r'hotjar\.com'],
                'name': 'Hotjar',
                'category': 'statistics'
            },
            'mixpanel': {
                'patterns': [r'mixpanel\.com'],
                'name': 'Mixpanel',
                'category': 'statistics'
            },
            'intercom': {
                'patterns': [r'intercom\.io', r'widget\.intercom\.io'],
                'name': 'Intercom',
                'category': 'functional'
            },
            'zendesk': {
                'patterns': [r'zendesk\.com', r'zdassets\.com'],
                'name': 'Zendesk',
                'category': 'functional'
            },
            'hubspot': {
                'patterns': [r'hubspot\.com', r'hs-scripts\.com'],
                'name': 'HubSpot',
                'category': 'marketing'
            },
            'mailchimp': {
                'patterns': [r'mailchimp\.com', r'list-manage\.com'],
                'name': 'Mailchimp',
                'category': 'marketing'
            },
            'stripe': {
                'patterns': [r'stripe\.com', r'js\.stripe\.com'],
                'name': 'Stripe',
                'category': 'functional'
            },
            'paypal': {
                'patterns': [r'paypal\.com', r'paypalobjects\.com'],
                'name': 'PayPal',
                'category': 'functional'
            },
            'youtube': {
                'patterns': [r'youtube\.com', r'ytimg\.com'],
                'name': 'YouTube',
                'category': 'marketing'
            },
            'twitter': {
                'patterns': [r'twitter\.com', r'twimg\.com'],
                'name': 'Twitter',
                'category': 'marketing'
            },
            'linkedin': {
                'patterns': [r'linkedin\.com', r'licdn\.com'],
                'name': 'LinkedIn',
                'category': 'marketing'
            },
            'tiktok': {
                'patterns': [r'tiktok\.com', r'bytedance\.com'],
                'name': 'TikTok',
                'category': 'marketing'
            }
        }
    
    def analyze_website(self, url, scan_id):
        """Analyze a website for compliance issues"""
        logger.info(f"[SCAN {scan_id}] Starting analysis for URL: {url}")
        
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            logger.info(f"[SCAN {scan_id}] Normalized URL: {url}")
            
            # Parse domain
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            logger.info(f"[SCAN {scan_id}] Extracted domain: {domain}")
            
            # Fetch website content
            logger.info(f"[SCAN {scan_id}] Fetching website content...")
            response = self._fetch_website(url, scan_id)
            
            if not response:
                logger.error(f"[SCAN {scan_id}] Failed to fetch website content")
                return self._create_error_result(url, domain, "Failed to fetch website content")
            
            logger.info(f"[SCAN {scan_id}] Successfully fetched content, size: {len(response.text)} characters")
            
            # Analyze content
            logger.info(f"[SCAN {scan_id}] Starting content analysis...")
            analysis_result = self._analyze_content(response.text, url, domain, scan_id)
            
            logger.info(f"[SCAN {scan_id}] Analysis complete. Compliance score: {analysis_result.get('compliance_score', 'N/A')}")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Analysis failed with error: {str(e)}")
            return self._create_error_result(url, domain if 'domain' in locals() else 'unknown', f"Analysis failed: {str(e)}")
    
    def _fetch_website(self, url, scan_id):
        """Fetch website content with proper error handling"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            logger.info(f"[SCAN {scan_id}] Making HTTP request to {url}")
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            
            logger.info(f"[SCAN {scan_id}] HTTP response: {response.status_code}")
            
            if response.status_code == 200:
                logger.info(f"[SCAN {scan_id}] Successfully fetched content")
                return response
            else:
                logger.warning(f"[SCAN {scan_id}] HTTP error: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"[SCAN {scan_id}] Request timeout after 15 seconds")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"[SCAN {scan_id}] Connection error")
            return None
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Fetch error: {str(e)}")
            return None
    
    def _analyze_content(self, html_content, url, domain, scan_id):
        """Analyze HTML content for compliance issues"""
        logger.info(f"[SCAN {scan_id}] Parsing HTML content...")
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            logger.info(f"[SCAN {scan_id}] HTML parsed successfully")
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] HTML parsing failed: {str(e)}")
            # Fallback to regex analysis
            soup = None
        
        # Analyze scripts and tracking
        logger.info(f"[SCAN {scan_id}] Analyzing scripts and tracking services...")
        scripts = self._analyze_scripts(html_content, soup, scan_id)
        
        # Analyze cookies
        logger.info(f"[SCAN {scan_id}] Analyzing cookies...")
        cookies = self._analyze_cookies(html_content, soup, scan_id)
        
        # Calculate compliance score
        logger.info(f"[SCAN {scan_id}] Calculating compliance score...")
        compliance_score = self._calculate_compliance_score(scripts, cookies, html_content, scan_id)
        
        # Calculate revenue potential
        logger.info(f"[SCAN {scan_id}] Calculating revenue potential...")
        revenue_data = self._calculate_revenue_potential(scripts, cookies, scan_id)
        
        # Create compliance breakdown
        compliance_breakdown = {
            'gdpr': {
                'score': max(0, compliance_score - 10),
                'issues': len([s for s in scripts if not s.get('consent_gated', False)]),
                'status': 'non-compliant' if compliance_score < 70 else 'compliant'
            },
            'ccpa': {
                'score': max(0, compliance_score - 5),
                'issues': len([c for c in cookies if c.get('category') == 'marketing']),
                'status': 'partially-compliant' if compliance_score < 80 else 'compliant'
            },
            'lgpd': {
                'score': compliance_score,
                'issues': len([s for s in scripts if s.get('tracking_service')]),
                'status': 'non-compliant' if compliance_score < 75 else 'compliant'
            }
        }
        
        result = {
            'scan_id': scan_id,
            'url': url,
            'domain': domain,
            'status': 'completed',
            'progress': 100,
            'compliance_score': compliance_score,
            'compliance_breakdown': compliance_breakdown,
            'scan_completed_at': datetime.utcnow().isoformat(),
            'cookies': cookies,
            'scripts': scripts,
            'potential_earnings': revenue_data['monthly'],
            'annual_earnings': revenue_data['annual'],
            'recommendations': [
                'Implement CookieBot.ai for instant GDPR compliance',
                'Start earning revenue from your consent banner today',
                'Reduce legal risk with proper cookie categorization',
                'Get 60% revenue share from affiliate partnerships'
            ]
        }
        
        logger.info(f"[SCAN {scan_id}] Final result: domain={domain}, score={compliance_score}, cookies={len(cookies)}, scripts={len(scripts)}")
        
        return result
    
    def _analyze_scripts(self, html_content, soup, scan_id):
        """Analyze scripts for tracking services"""
        scripts = []
        
        try:
            # Parse script tags if soup is available
            if soup:
                script_tags = soup.find_all('script')
                logger.info(f"[SCAN {scan_id}] Found {len(script_tags)} script tags")
                
                for script in script_tags:
                    src = script.get('src', '')
                    content = script.string or ''
                    
                    # Check for tracking services
                    for service_id, service_info in self.tracking_services.items():
                        for pattern in service_info['patterns']:
                            if re.search(pattern, src + content, re.IGNORECASE):
                                scripts.append({
                                    'type': 'external' if src else 'inline',
                                    'src': src,
                                    'tracking_service': service_id,
                                    'service_name': service_info['name'],
                                    'category': service_info['category'],
                                    'consent_gated': False  # Assume not gated unless detected
                                })
                                break
            
            # Fallback regex analysis
            else:
                logger.info(f"[SCAN {scan_id}] Using regex fallback for script analysis")
                for service_id, service_info in self.tracking_services.items():
                    for pattern in service_info['patterns']:
                        if re.search(pattern, html_content, re.IGNORECASE):
                            scripts.append({
                                'type': 'detected',
                                'src': '',
                                'tracking_service': service_id,
                                'service_name': service_info['name'],
                                'category': service_info['category'],
                                'consent_gated': False
                            })
                            break
            
            logger.info(f"[SCAN {scan_id}] Detected {len(scripts)} tracking scripts")
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Script analysis error: {str(e)}")
        
        return scripts
    
    def _analyze_cookies(self, html_content, soup, scan_id):
        """Analyze potential cookies"""
        cookies = []
        
        try:
            # Common cookie patterns
            cookie_patterns = {
                '_ga': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users'},
                '_gid': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users'},
                '_gat': {'category': 'statistics', 'purpose': 'Google Analytics - Used to throttle request rate'},
                '_fbp': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions'},
                '_fbc': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions'},
                'PHPSESSID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality'},
                'JSESSIONID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality'},
                '__stripe_mid': {'category': 'functional', 'purpose': 'Stripe - Payment processing'},
                '__stripe_sid': {'category': 'functional', 'purpose': 'Stripe - Payment processing'},
                '_hjid': {'category': 'statistics', 'purpose': 'Hotjar - User behavior analytics'},
                '_hjFirstSeen': {'category': 'statistics', 'purpose': 'Hotjar - User behavior analytics'},
                'mp_': {'category': 'statistics', 'purpose': 'Mixpanel - Analytics and tracking'},
                'intercom-': {'category': 'functional', 'purpose': 'Intercom - Customer support chat'},
                '__hstc': {'category': 'marketing', 'purpose': 'HubSpot - Marketing automation'},
                '__hssc': {'category': 'marketing', 'purpose': 'HubSpot - Marketing automation'},
                '__hssrc': {'category': 'marketing', 'purpose': 'HubSpot - Marketing automation'}
            }
            
            # Look for cookie references in the HTML
            for cookie_name, cookie_info in cookie_patterns.items():
                if cookie_name in html_content:
                    cookies.append({
                        'name': cookie_name,
                        'category': cookie_info['category'],
                        'purpose': cookie_info['purpose'],
                        'domain': '',  # Would need actual cookie inspection
                        'secure': False,  # Default assumption
                        'http_only': cookie_info['category'] == 'necessary'
                    })
            
            logger.info(f"[SCAN {scan_id}] Detected {len(cookies)} potential cookies")
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Cookie analysis error: {str(e)}")
        
        return cookies
    
    def _calculate_compliance_score(self, scripts, cookies, html_content, scan_id):
        """Calculate overall compliance score"""
        try:
            score = 100
            
            # Deduct points for tracking without consent
            tracking_scripts = [s for s in scripts if s.get('tracking_service')]
            score -= len(tracking_scripts) * 15
            
            # Deduct points for marketing cookies
            marketing_cookies = [c for c in cookies if c.get('category') == 'marketing']
            score -= len(marketing_cookies) * 10
            
            # Check for consent banner
            consent_indicators = ['cookie', 'consent', 'privacy', 'gdpr', 'accept', 'decline']
            has_consent_banner = any(indicator in html_content.lower() for indicator in consent_indicators)
            
            if not has_consent_banner:
                score -= 25
            
            # Ensure score is between 0 and 100
            score = max(0, min(100, score))
            
            logger.info(f"[SCAN {scan_id}] Calculated compliance score: {score}")
            
            return score
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Score calculation error: {str(e)}")
            return 0
    
    def _calculate_revenue_potential(self, scripts, cookies, scan_id):
        """Calculate revenue potential"""
        try:
            # Base revenue calculation
            base_monthly = 100
            
            # Add revenue based on tracking services (more tracking = more revenue potential)
            tracking_count = len([s for s in scripts if s.get('tracking_service')])
            revenue_per_service = 50
            
            monthly = base_monthly + (tracking_count * revenue_per_service)
            annual = monthly * 12
            
            logger.info(f"[SCAN {scan_id}] Calculated revenue: monthly=${monthly}, annual=${annual}")
            
            return {
                'monthly': monthly,
                'annual': annual
            }
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Revenue calculation error: {str(e)}")
            return {'monthly': 100, 'annual': 1200}
    
    def _create_error_result(self, url, domain, error_message):
        """Create error result when analysis fails"""
        return {
            'scan_id': str(uuid.uuid4()),
            'url': url,
            'domain': domain,
            'status': 'error',
            'progress': 100,
            'compliance_score': 0,
            'compliance_breakdown': {
                'gdpr': {'score': 0, 'issues': 0, 'status': 'error'},
                'ccpa': {'score': 0, 'issues': 0, 'status': 'error'},
                'lgpd': {'score': 0, 'issues': 0, 'status': 'error'}
            },
            'error': error_message,
            'scan_completed_at': datetime.utcnow().isoformat(),
            'cookies': [],
            'scripts': [],
            'potential_earnings': 0,
            'annual_earnings': 0,
            'recommendations': [
                'Please check the URL and try again',
                'Ensure the website is accessible',
                'Contact support if the issue persists'
            ]
        }

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
        company = data.get('company', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Check if user exists
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({'error': 'User already exists'}), 409
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Create user
            cur.execute("""
                INSERT INTO users (email, password_hash, first_name, last_name, company)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, email, first_name, last_name, company, subscription_tier, revenue_balance, created_at
            """, (email, password_hash, first_name, last_name, company))
            
            user = cur.fetchone()
            conn.commit()
            
            # Create access token - FIX: Convert user ID to string
            access_token = create_access_token(identity=str(user['id']))
            
            return jsonify({
                'message': 'User created successfully',
                'access_token': access_token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'company': user['company'],
                    'subscription_tier': user['subscription_tier'],
                    'revenue_balance': float(user['revenue_balance'])
                }
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Registration error: {e}")
            return jsonify({'error': f'Registration failed: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user
            cur.execute("""
                SELECT id, email, password_hash, first_name, last_name, company, 
                       subscription_tier, revenue_balance
                FROM users WHERE email = %s
            """, (email,))
            
            user = cur.fetchone()
            
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Create access token - FIX: Convert user ID to string
            access_token = create_access_token(identity=str(user['id']))
            
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'company': user['company'],
                    'subscription_tier': user['subscription_tier'],
                    'revenue_balance': float(user['revenue_balance'])
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': f'Login failed: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

# User profile routes
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        # FIX: Convert JWT identity back to integer
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT id, email, first_name, last_name, company, 
                       subscription_tier, revenue_balance, created_at
                FROM users WHERE id = %s
            """, (user_id,))
            
            user = cur.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'company': user['company'],
                    'subscription_tier': user['subscription_tier'],
                    'revenue_balance': float(user['revenue_balance']),
                    'created_at': user['created_at'].isoformat() if user['created_at'] else None
                }
            }), 200
            
        except Exception as e:
            logger.error(f"Profile error: {e}")
            return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500

# Website management routes
@app.route('/api/websites', methods=['GET'])
@jwt_required()
def get_websites():
    try:
        # FIX: Convert JWT identity back to integer
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT id, domain, status, visitors_today, consent_rate, 
                       revenue_today, created_at
                FROM websites WHERE user_id = %s
                ORDER BY created_at DESC
            """, (user_id,))
            
            websites = cur.fetchall()
            
            websites_list = []
            for website in websites:
                websites_list.append({
                    'id': website['id'],
                    'domain': website['domain'],
                    'status': website['status'],
                    'visitors_today': website['visitors_today'],
                    'consent_rate': float(website['consent_rate']),
                    'revenue_today': float(website['revenue_today']),
                    'created_at': website['created_at'].isoformat() if website['created_at'] else None
                })
            
            return jsonify({'websites': websites_list}), 200
            
        except Exception as e:
            logger.error(f"Get websites error: {e}")
            return jsonify({'error': f'Failed to get websites: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Get websites error: {e}")
        return jsonify({'error': f'Failed to get websites: {str(e)}'}), 500

@app.route('/api/websites', methods=['POST'])
@jwt_required()
def add_website():
    try:
        # FIX: Convert JWT identity back to integer
        user_id = int(get_jwt_identity())
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Clean domain (remove protocol, www, trailing slash)
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').rstrip('/')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Check if domain already exists for this user
            cur.execute("SELECT id FROM websites WHERE user_id = %s AND domain = %s", (user_id, domain))
            if cur.fetchone():
                return jsonify({'error': 'Domain already exists'}), 409
            
            # Generate integration code
            integration_code = f"""
<!-- CookieBot.ai Integration Code -->
<script>
(function() {{
    var script = document.createElement('script');
    script.src = 'https://api.cookiebot.ai/js/cookiebot.js';
    script.setAttribute('data-website-id', '{uuid.uuid4()}');
    script.setAttribute('data-domain', '{domain}');
    document.head.appendChild(script);
}})();
</script>
""".strip()
            
            # Add new website
            cur.execute("""
                INSERT INTO websites (user_id, domain, integration_code)
                VALUES (%s, %s, %s)
                RETURNING id, domain, status, visitors_today, consent_rate, revenue_today, created_at
            """, (user_id, domain, integration_code))
            
            website = cur.fetchone()
            conn.commit()
            
            return jsonify({
                'message': 'Website added successfully',
                'website': {
                    'id': website['id'],
                    'domain': website['domain'],
                    'status': website['status'],
                    'visitors_today': website['visitors_today'],
                    'consent_rate': float(website['consent_rate']),
                    'revenue_today': float(website['revenue_today']),
                    'integration_code': integration_code
                }
            }), 201
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Add website error: {e}")
            return jsonify({'error': f'Failed to add website: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Add website error: {e}")
        return jsonify({'error': f'Failed to add website: {str(e)}'}), 500

# Analytics routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_analytics():
    try:
        # FIX: Convert JWT identity back to integer
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get user's total revenue
            cur.execute("""
                SELECT COALESCE(revenue_balance, 0) as total_revenue
                FROM users WHERE id = %s
            """, (user_id,))
            revenue_result = cur.fetchone()
            total_revenue = float(revenue_result['total_revenue']) if revenue_result else 0.0
            
            # Get total visitors (sum of all websites)
            cur.execute("""
                SELECT COALESCE(SUM(visitors_today), 0) as total_visitors
                FROM websites WHERE user_id = %s
            """, (user_id,))
            visitors_result = cur.fetchone()
            total_visitors = visitors_result['total_visitors'] if visitors_result else 0
            
            # Get average consent rate
            cur.execute("""
                SELECT COALESCE(AVG(consent_rate), 0) as avg_consent_rate
                FROM websites WHERE user_id = %s AND visitors_today > 0
            """, (user_id,))
            consent_result = cur.fetchone()
            avg_consent_rate = float(consent_result['avg_consent_rate']) if consent_result else 0.0
            
            # Get website count
            cur.execute("""
                SELECT COUNT(*) as website_count
                FROM websites WHERE user_id = %s
            """, (user_id,))
            count_result = cur.fetchone()
            website_count = count_result['website_count'] if count_result else 0
            
            return jsonify({
                'revenue': total_revenue,
                'visitors': total_visitors,
                'consent_rate': avg_consent_rate,
                'websites': website_count
            }), 200
            
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500

# Public tracking route (no auth required)
@app.route('/api/public/track', methods=['POST'])
def track_event():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        event_type = data.get('event_type', 'page_view')
        visitor_id = data.get('visitor_id')
        consent_given = data.get('consent_given')
        
        if not website_id:
            return jsonify({'error': 'Website ID is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Calculate revenue (example: $0.01 per visitor, $0.05 if consent given)
            revenue = 0.05 if consent_given else 0.01
            
            # Insert analytics event
            cur.execute("""
                INSERT INTO analytics_events (website_id, event_type, visitor_id, consent_given, revenue_generated, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (website_id, event_type, visitor_id, consent_given, revenue, json.dumps(data)))
            
            event_id = cur.fetchone()['id']
            
            # Update website stats
            cur.execute("""
                UPDATE websites 
                SET visitors_today = visitors_today + 1,
                    revenue_today = revenue_today + %s,
                    consent_rate = (
                        SELECT COALESCE(AVG(CASE WHEN consent_given THEN 100.0 ELSE 0.0 END), 0)
                        FROM analytics_events 
                        WHERE website_id = %s AND created_at >= CURRENT_DATE
                    )
                WHERE id = %s
            """, (revenue, website_id, website_id))
            
            conn.commit()
            
            return jsonify({
                'message': 'Event tracked successfully',
                'event_id': event_id,
                'revenue_generated': revenue
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Tracking error: {e}")
            return jsonify({'error': f'Failed to track event: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Tracking error: {e}")
        return jsonify({'error': f'Failed to track event: {str(e)}'}), 500

# Cookie scan route (no auth required)
@app.route('/api/cookie-scan', methods=['POST'])
def cookie_scan():
    """
    Receive and process cookie scan data from CookieBot.ai scripts
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        client_id = data.get('clientId')
        domain = data.get('domain')
        cookies = data.get('cookies', [])
        timestamp = data.get('timestamp')
        
        if not all([client_id, domain]):
            return jsonify({'error': 'Missing required fields: clientId, domain'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Find or create website record
            cur.execute("""
                SELECT id, user_id FROM websites 
                WHERE integration_code LIKE %s OR domain = %s
                LIMIT 1
            """, (f'%{client_id}%', domain))
            
            website = cur.fetchone()
            
            if not website:
                # Create a basic website record for tracking
                cur.execute("""
                    INSERT INTO websites (user_id, domain, status, integration_code)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, user_id
                """, (
                    1,  # Default user ID for unregistered domains
                    domain,
                    'active',
                    f'<!-- CookieBot.ai Client ID: {client_id} -->'
                ))
                website = cur.fetchone()
                conn.commit()
            
            website_id = website['id']
            user_id = website['user_id']
            
            # Process each cookie/script detected
            total_cookies = len(cookies)
            marketing_cookies = len([c for c in cookies if c.get('category') == 'marketing'])
            statistics_cookies = len([c for c in cookies if c.get('category') == 'statistics'])
            functional_cookies = len([c for c in cookies if c.get('category') == 'functional'])
            
            # Store the scan event
            cur.execute("""
                INSERT INTO analytics_events (
                    website_id, 
                    event_type, 
                    visitor_id, 
                    consent_given, 
                    revenue_generated, 
                    metadata, 
                    created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                website_id,
                'cookie_scan',
                f"scan_{client_id}_{int(time.time())}",
                None,
                0.00,
                json.dumps({
                    'client_id': client_id,
                    'domain': domain,
                    'total_cookies': total_cookies,
                    'marketing_cookies': marketing_cookies,
                    'statistics_cookies': statistics_cookies,
                    'functional_cookies': functional_cookies,
                    'cookies_detected': cookies,
                    'scan_timestamp': timestamp
                }),
                timestamp or datetime.utcnow().isoformat()
            ))
            
            scan_event_id = cur.fetchone()['id']
            
            # Update website statistics
            cur.execute("""
                UPDATE websites 
                SET 
                    visitors_today = visitors_today + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (website_id,))
            
            # Calculate compliance score
            compliance_score = 100
            if marketing_cookies > 0:
                compliance_score -= (marketing_cookies * 15)
            if statistics_cookies > 0:
                compliance_score -= (statistics_cookies * 10)
            if functional_cookies > 3:
                compliance_score -= ((functional_cookies - 3) * 5)
            
            compliance_score = max(0, min(100, compliance_score))
            
            conn.commit()
            
            logger.info(f"Cookie scan processed: domain={domain}, client_id={client_id}, cookies={total_cookies}, score={compliance_score}")
            
            return jsonify({
                'success': True,
                'scan_id': scan_event_id,
                'website_id': website_id,
                'compliance_score': compliance_score,
                'cookies_detected': total_cookies,
                'breakdown': {
                    'marketing': marketing_cookies,
                    'statistics': statistics_cookies,
                    'functional': functional_cookies,
                    'necessary': total_cookies - marketing_cookies - statistics_cookies - functional_cookies
                },
                'recommendations': [
                    'Implement proper consent management for marketing cookies',
                    'Consider reducing third-party tracking scripts',
                    'Ensure all cookies have proper categorization'
                ] if compliance_score < 80 else [
                    'Good compliance detected',
                    'Continue monitoring cookie usage',
                    'Consider implementing Privacy Insights for revenue'
                ],
                'timestamp': timestamp or datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Cookie scan processing error: {str(e)}")
            return jsonify({'error': f'Failed to process scan: {str(e)}'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Cookie scan error: {str(e)}")
        return jsonify({'error': f'Cookie scan failed: {str(e)}'}), 500

# Real compliance scanning routes
@app.route('/api/compliance/real-scan', methods=['POST'])
@jwt_required()
def start_real_compliance_scan():
    """Start a real compliance scan"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan in memory
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'results': None,
            'started_at': datetime.utcnow().isoformat()
        }
        
        logger.info(f"[SCAN {scan_id}] Starting real compliance scan for URL: {url}")
        
        # Start analysis in background thread
        def run_analysis():
            try:
                analyzer = RealWebsiteAnalyzer()
                results = analyzer.analyze_website(url, scan_id)
                
                # Update scan results
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['progress'] = 100
                active_scans[scan_id]['results'] = results
                active_scans[scan_id]['completed_at'] = datetime.utcnow().isoformat()
                
                logger.info(f"[SCAN {scan_id}] Scan completed successfully")
                
            except Exception as e:
                logger.error(f"[SCAN {scan_id}] Background analysis failed: {str(e)}")
                active_scans[scan_id]['status'] = 'error'
                active_scans[scan_id]['progress'] = 100
                active_scans[scan_id]['error'] = str(e)
        
        # Start background thread
        thread = threading.Thread(target=run_analysis)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'running',
            'message': 'Compliance scan started successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error starting real scan: {e}")
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500

@app.route('/api/compliance/real-scan/<scan_id>/status', methods=['GET'])
@jwt_required()
def get_real_scan_status(scan_id):
    """Get the status of a real compliance scan"""
    try:
        if scan_id not in active_scans:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan_data = active_scans[scan_id]
        
        response = {
            'scan_id': scan_id,
            'status': scan_data['status'],
            'progress': scan_data['progress'],
            'started_at': scan_data['started_at']
        }
        
        if scan_data['status'] == 'completed' and scan_data.get('results'):
            response['results'] = scan_data['results']
        elif scan_data['status'] == 'error':
            response['error'] = scan_data.get('error', 'Unknown error')
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': f'Failed to get scan status: {str(e)}'}), 500

# ===== PRIVACY INSIGHTS API ENDPOINTS =====

@app.route('/api/privacy-insights', methods=['POST'])
def get_privacy_insights():
    """
    Get privacy insights content for the widget
    """
    try:
        data = request.get_json()
        client_id = data.get('clientId')
        domain = data.get('domain')
        language = data.get('language', 'en')
        context = data.get('context', {})
        
        if not client_id:
            return jsonify({'error': 'Client ID required'}), 400
        
        # Get language code
        lang_code = language.split('-')[0] if language else 'en'
        
        # Privacy insights content library
        insights_library = {
            'en': [
                {
                    'id': 'password-security',
                    'title': 'Strengthen Your Password Security',
                    'description': 'Use unique passwords for each account and enable two-factor authentication to protect your personal data.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.15  # Cost per click for revenue calculation
                },
                {
                    'id': 'privacy-settings',
                    'title': 'Review Your Social Media Privacy',
                    'description': 'Check your privacy settings on social platforms to control who can see your personal information.',
                    'category': 'privacy',
                    'sponsored': True,
                    'cpc': 0.12
                },
                {
                    'id': 'data-backup',
                    'title': 'Backup Your Important Data',
                    'description': 'Regular backups protect against data loss from cyber attacks, hardware failure, or accidental deletion.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.18
                },
                {
                    'id': 'browser-privacy',
                    'title': 'Enhance Your Browser Privacy',
                    'description': 'Use private browsing mode and clear cookies regularly to reduce online tracking.',
                    'category': 'privacy',
                    'sponsored': True,
                    'cpc': 0.14
                },
                {
                    'id': 'wifi-security',
                    'title': 'Secure Your WiFi Connection',
                    'description': 'Avoid public WiFi for sensitive activities and use a VPN to encrypt your internet connection.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.20
                },
                {
                    'id': 'email-protection',
                    'title': 'Protect Your Email Privacy',
                    'description': 'Be cautious with email attachments and links, and use encrypted email services when possible.',
                    'category': 'privacy',
                    'sponsored': True,
                    'cpc': 0.16
                }
            ],
            'es': [
                {
                    'id': 'password-security',
                    'title': 'Fortalece la Seguridad de tus Contraseñas',
                    'description': 'Usa contraseñas únicas para cada cuenta y activa la autenticación de dos factores.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.15
                },
                {
                    'id': 'privacy-settings',
                    'title': 'Revisa tu Privacidad en Redes Sociales',
                    'description': 'Verifica la configuración de privacidad en plataformas sociales para controlar quién ve tu información.',
                    'category': 'privacy',
                    'sponsored': True,
                    'cpc': 0.12
                },
                {
                    'id': 'data-backup',
                    'title': 'Respalda tus Datos Importantes',
                    'description': 'Los respaldos regulares protegen contra la pérdida de datos por ataques cibernéticos o fallas de hardware.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.18
                }
            ],
            'fr': [
                {
                    'id': 'password-security',
                    'title': 'Renforcez la Sécurité de vos Mots de Passe',
                    'description': 'Utilisez des mots de passe uniques et activez l\'authentification à deux facteurs.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.15
                },
                {
                    'id': 'privacy-settings',
                    'title': 'Vérifiez vos Paramètres de Confidentialité',
                    'description': 'Contrôlez vos paramètres de confidentialité sur les réseaux sociaux pour protéger vos informations.',
                    'category': 'privacy',
                    'sponsored': True,
                    'cpc': 0.12
                },
                {
                    'id': 'data-backup',
                    'title': 'Sauvegardez vos Données Importantes',
                    'description': 'Les sauvegardes régulières protègent contre la perte de données due aux cyberattaques.',
                    'category': 'security',
                    'sponsored': True,
                    'cpc': 0.18
                }
            ]
        }
        
        # Get insights for the requested language
        insights = insights_library.get(lang_code, insights_library['en'])
        
        # Log the request
        logger.info(f"Privacy insights requested for client {client_id}, domain {domain}, language {lang_code}")
        
        return jsonify(insights)
        
    except Exception as e:
        logger.error(f"Error getting privacy insights: {str(e)}")
        return jsonify({'error': 'Failed to get privacy insights'}), 500


@app.route('/api/privacy-insight-click', methods=['POST'])
def track_privacy_insight_click():
    """
    Track privacy insight clicks for revenue sharing
    """
    try:
        data = request.get_json()
        client_id = data.get('clientId')
        insight_id = data.get('insightId')
        domain = data.get('domain')
        timestamp = data.get('timestamp')
        revenue_share = data.get('revenueShare', 0.6)  # Default 60% to website owner
        
        if not all([client_id, insight_id, domain]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Calculate revenue based on insight CPC
        insight_cpc_map = {
            'password-security': 0.15,
            'privacy-settings': 0.12,
            'data-backup': 0.18,
            'browser-privacy': 0.14,
            'wifi-security': 0.20,
            'email-protection': 0.16
        }
        
        base_revenue = insight_cpc_map.get(insight_id, 0.15)
        website_owner_revenue = base_revenue * revenue_share
        platform_revenue = base_revenue * (1 - revenue_share)
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Store the click event in analytics_events table
            cur.execute("""
                INSERT INTO analytics_events (website_id, event_type, visitor_id, consent_given, revenue_generated, metadata, created_at)
                VALUES (
                    (SELECT id FROM websites WHERE integration_code LIKE %s LIMIT 1),
                    'privacy_insight_click',
                    %s,
                    true,
                    %s,
                    %s,
                    %s
                )
            """, (
                f'%{client_id}%',  # Search for client_id in integration_code
                f"privacy_insight_{insight_id}_{int(time.time())}",  # Unique visitor ID
                website_owner_revenue,
                json.dumps({
                    'insight_id': insight_id,
                    'domain': domain,
                    'base_revenue': base_revenue,
                    'revenue_share': revenue_share,
                    'platform_revenue': platform_revenue
                }),
                timestamp or datetime.utcnow().isoformat()
            ))
            
            # Update user's revenue balance
            cur.execute("""
                UPDATE users 
                SET revenue_balance = COALESCE(revenue_balance, 0) + %s
                WHERE id = (
                    SELECT user_id FROM websites WHERE integration_code LIKE %s LIMIT 1
                )
            """, (website_owner_revenue, f'%{client_id}%'))
            
            conn.commit()
            
            logger.info(f"Privacy insight click tracked: {insight_id} for client {client_id}, revenue: ${website_owner_revenue:.4f}")
            
            return jsonify({
                'success': True,
                'revenue': website_owner_revenue,
                'insight_id': insight_id,
                'timestamp': timestamp
            })
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Error tracking privacy insight click: {str(e)}")
            return jsonify({'error': 'Failed to track click'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Error tracking privacy insight click: {str(e)}")
        return jsonify({'error': 'Failed to track click'}), 500


@app.route('/api/privacy-insights/stats', methods=['GET'])
@jwt_required()
def get_privacy_insights_stats():
    """
    Get privacy insights statistics for dashboard
    """
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get total privacy insight clicks and revenue
            cur.execute("""
                SELECT 
                    COUNT(*) as total_clicks,
                    COALESCE(SUM(revenue_generated), 0) as total_revenue,
                    COUNT(DISTINCT DATE(created_at)) as active_days
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '30 days'
            """, (current_user_id,))
            
            stats = cur.fetchone()
            
            # Get daily breakdown for the last 7 days
            cur.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as clicks,
                    COALESCE(SUM(revenue_generated), 0) as revenue
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '7 days'
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """, (current_user_id,))
            
            daily_stats = cur.fetchall()
            
            # Get top performing insights
            cur.execute("""
                SELECT 
                    ae.metadata->>'insight_id' as insight_id,
                    COUNT(*) as clicks,
                    COALESCE(SUM(revenue_generated), 0) as revenue
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s 
                AND ae.event_type = 'privacy_insight_click'
                AND ae.created_at >= NOW() - INTERVAL '30 days'
                GROUP BY ae.metadata->>'insight_id'
                ORDER BY revenue DESC
                LIMIT 5
            """, (current_user_id,))
            
            top_insights = cur.fetchall()
            
            return jsonify({
                'total_clicks': stats[0] if stats else 0,
                'total_revenue': float(stats[1]) if stats else 0.0,
                'active_days': stats[2] if stats else 0,
                'daily_stats': [
                    {
                        'date': str(row[0]),
                        'clicks': row[1],
                        'revenue': float(row[2])
                    } for row in daily_stats
                ],
                'top_insights': [
                    {
                        'insight_id': row[0],
                        'clicks': row[1],
                        'revenue': float(row[2])
                    } for row in top_insights
                ]
            })
            
        except Exception as e:
            logger.error(f"Error getting privacy insights stats: {str(e)}")
            return jsonify({'error': 'Failed to get stats'}), 500
        finally:
            conn.close()
        
    except Exception as e:
        logger.error(f"Error getting privacy insights stats: {str(e)}")
        return jsonify({'error': 'Failed to get stats'}), 500


@app.route('/api/privacy-insights/config', methods=['GET', 'POST'])
@jwt_required()
def privacy_insights_config():
    """
    Get or update privacy insights configuration for a website
    """
    try:
        current_user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            if request.method == 'GET':
                website_id = request.args.get('website_id')
                if not website_id:
                    return jsonify({'error': 'Website ID required'}), 400
                
                cur = conn.cursor()
                cur.execute("""
                    SELECT integration_code, domain, status
                    FROM websites 
                    WHERE id = %s AND user_id = %s
                """, (website_id, current_user_id))
                
                website = cur.fetchone()
                if not website:
                    return jsonify({'error': 'Website not found'}), 404
                
                # Default privacy insights configuration
                config = {
                    'enabled': True,
                    'widget_delay': 3000,  # 3 seconds
                    'widget_duration': 15000,  # 15 seconds
                    'revenue_share': 0.6,  # 60% to website owner
                    'language': 'auto',
                    'categories': ['security', 'privacy']
                }
                
                return jsonify({
                    'website': {
                        'id': website_id,
                        'domain': website[1],
                        'integration_code': website[0],
                        'status': website[2]
                    },
                    'privacy_insights_config': config
                })
            
            elif request.method == 'POST':
                data = request.get_json()
                website_id = data.get('website_id')
                config = data.get('config', {})
                
                if not website_id:
                    return jsonify({'error': 'Website ID required'}), 400
                
                # Validate website ownership
                cur = conn.cursor()
                cur.execute("""
                    SELECT id FROM websites 
                    WHERE id = %s AND user_id = %s
                """, (website_id, current_user_id))
                
                if not cur.fetchone():
                    return jsonify({'error': 'Website not found'}), 404
                
                # In a full implementation, you would store this config in a separate table
                # For now, we'll just return success
                logger.info(f"Privacy insights config updated for website {website_id}: {config}")
                
                return jsonify({
                    'success': True,
                    'message': 'Privacy insights configuration updated',
                    'config': config
                })
                
        except Exception as e:
            logger.error(f"Error handling privacy insights config: {str(e)}")
            return jsonify({'error': 'Failed to handle config'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Error handling privacy insights config: {str(e)}")
        return jsonify({'error': 'Failed to handle config'}), 500

# ===== CONTACT FORM API ENDPOINT =====

@app.route('/api/contact', methods=['POST'])
def contact_form():
    """
    Handle contact form submissions
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'message']
        for field in required_fields:
            if not data.get(field) or not data[field].strip():
                return jsonify({
                    'success': False,
                    'error': f'{field.capitalize()} is required'
                }), 400
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, data['email']):
            return jsonify({
                'success': False,
                'error': 'Please enter a valid email address'
            }), 400
        
        # Sanitize inputs
        name = data['name'].strip()[:100]  # Limit length
        email = data['email'].strip()[:100]
        company = data.get('company', '').strip()[:100]
        subject = data.get('subject', '').strip()[:200]
        message = data['message'].strip()[:2000]  # Limit message length
        inquiry_type = data.get('inquiryType', 'general').strip()[:50]
        
        # Create email content
        email_subject = f"New Contact Form Submission - {name}"
        if subject:
            email_subject = f"New Contact: {subject} - {name}"
        
        email_body = f"""
New contact form submission from CookieBot.ai website:

Name: {name}
Email: {email}
Company: {company if company else 'Not provided'}
Inquiry Type: {inquiry_type}
Subject: {subject if subject else 'Not provided'}

Message:
{message}

Submitted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
IP Address: {request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'Unknown'))}
User Agent: {request.environ.get('HTTP_USER_AGENT', 'Unknown')}
"""
        
        # Send email using environment variables for configuration
        try:
            # You'll need to set these environment variables in Vercel
            smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
            smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            smtp_username = os.environ.get('SMTP_USERNAME')  # Your email
            smtp_password = os.environ.get('SMTP_PASSWORD')  # App password
            
            if not smtp_username or not smtp_password:
                # Fallback: Log to console and save to database
                logger.info(f"Contact form submission: {email_body}")
                
                # Save to database for manual review
                try:
                    conn = get_db_connection()
                    if conn:
                        cur = conn.cursor()
                        cur.execute("""
                            INSERT INTO analytics_events (website_id, event_type, visitor_id, metadata, created_at)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            1,  # Default website ID for contact forms
                            'contact_form_submission',
                            email,  # Use email as visitor ID
                            json.dumps({
                                'name': name,
                                'email': email,
                                'company': company,
                                'subject': subject,
                                'message': message,
                                'inquiry_type': inquiry_type,
                                'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
                                'user_agent': request.environ.get('HTTP_USER_AGENT')
                            }),
                            datetime.now()
                        ))
                        conn.commit()
                        conn.close()
                except Exception as db_error:
                    logger.error(f"Database error: {db_error}")
                
                return jsonify({
                    'success': True,
                    'message': 'Thank you for your message! We will get back to you within 24 hours.'
                })
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = smtp_username
            msg['To'] = 'info@cookiebot.ai'
            msg['Subject'] = email_subject
            msg['Reply-To'] = email  # Allow direct reply to the sender
            
            # Add body to email
            msg.attach(MIMEText(email_body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            text = msg.as_string()
            server.sendmail(smtp_username, 'info@cookiebot.ai', text)
            server.quit()
            
            # Also save to database for tracking
            try:
                conn = get_db_connection()
                if conn:
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO analytics_events (website_id, event_type, visitor_id, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        1,  # Default website ID for contact forms
                        'contact_form_submission',
                        email,  # Use email as visitor ID
                        json.dumps({
                            'name': name,
                            'email': email,
                            'company': company,
                            'subject': subject,
                            'message': message,
                            'inquiry_type': inquiry_type,
                            'email_sent': True,
                            'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
                            'user_agent': request.environ.get('HTTP_USER_AGENT')
                        }),
                        datetime.now()
                    ))
                    conn.commit()
                    conn.close()
            except Exception as db_error:
                logger.error(f"Database error: {db_error}")
            
            return jsonify({
                'success': True,
                'message': 'Thank you for your message! We will get back to you within 24 hours.'
            })
            
        except Exception as email_error:
            logger.error(f"Email error: {email_error}")
            
            # Save to database even if email fails
            try:
                conn = get_db_connection()
                if conn:
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO analytics_events (website_id, event_type, visitor_id, metadata, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        1,  # Default website ID for contact forms
                        'contact_form_submission',
                        email,  # Use email as visitor ID
                        json.dumps({
                            'name': name,
                            'email': email,
                            'company': company,
                            'subject': subject,
                            'message': message,
                            'inquiry_type': inquiry_type,
                            'email_sent': False,
                            'email_error': str(email_error),
                            'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
                            'user_agent': request.environ.get('HTTP_USER_AGENT')
                        }),
                        datetime.now()
                    ))
                    conn.commit()
                    conn.close()
            except Exception as db_error:
                logger.error(f"Database error: {db_error}")
            
            return jsonify({
                'success': True,
                'message': 'Thank you for your message! We have received it and will get back to you soon.'
            })
    
    except Exception as e:
        logger.error(f"Contact form error: {e}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while sending your message. Please try again later.'
        }), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'timestamp': datetime.utcnow().isoformat()
            }), 500
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 as test, version() as db_version")
            result = cur.fetchone()
            cur.close()
            conn.close()
            
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'database': 'connected',
                'database_version': result['db_version'][:100] if result else 'unknown',
                'environment_vars': {
                    'DATABASE_URL': bool(os.environ.get('DATABASE_URL')),
                    'JWT_SECRET_KEY': bool(os.environ.get('JWT_SECRET_KEY')),
                    'SUPABASE_URL': bool(os.environ.get('SUPABASE_URL'))
                },
                'active_scans': len(active_scans)
            }), 200
            
        except Exception as e:
            conn.close()
            logger.error(f"Health check database error: {e}")
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'database': 'disconnected',
                'error': str(e)
            }), 500
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API',
        'version': '2.0.0',
        'status': 'running',
        'endpoints': {
            'health': '/api/health',
            'auth': {
                'register': '/api/auth/register',
                'login': '/api/auth/login'
            },
            'user': {
                'profile': '/api/user/profile'
            },
            'websites': '/api/websites',
            'analytics': {
                'dashboard': '/api/analytics/dashboard'
            },
            'tracking': '/api/public/track',
            'cookie_scan': '/api/cookie-scan',
            'compliance': {
                'real_scan': '/api/compliance/real-scan',
                'scan_status': '/api/compliance/real-scan/<scan_id>/status'
            },
            'privacy_insights': {
                'content': '/api/privacy-insights',
                'click_tracking': '/api/privacy-insight-click',
                'stats': '/api/privacy-insights/stats',
                'config': '/api/privacy-insights/config'
            },
            'contact': '/api/contact'
        }
    }), 200

# Compliance health check endpoint
@app.route('/api/compliance/health', methods=['GET'])
def compliance_health_check():
    """Health check endpoint for compliance scanner"""
    return jsonify({
        'status': 'healthy',
        'service': 'compliance-scanner',
        'timestamp': datetime.utcnow().isoformat(),
        'active_scans': len(active_scans)
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

