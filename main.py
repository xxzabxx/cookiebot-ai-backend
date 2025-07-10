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
import threading
import time
import re
from urllib.parse import urljoin, urlparse

# Try to import BeautifulSoup with fallback
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
jwt = JWTManager(app)
CORS(app, origins=["*"])  # Allow all origins for development

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
                company_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

class RealWebsiteAnalyzer:
    """Real website analyzer that actually scans websites for compliance issues"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Known tracking scripts and their purposes
        self.tracking_scripts = {
            'googletagmanager.com': {'service': 'Google Tag Manager', 'category': 'statistics'},
            'google-analytics.com': {'service': 'Google Analytics', 'category': 'statistics'},
            'googleadservices.com': {'service': 'Google Ads', 'category': 'marketing'},
            'facebook.net': {'service': 'Facebook Pixel', 'category': 'marketing'},
            'doubleclick.net': {'service': 'Google DoubleClick', 'category': 'marketing'},
            'hotjar.com': {'service': 'Hotjar', 'category': 'statistics'},
            'mixpanel.com': {'service': 'Mixpanel', 'category': 'statistics'},
            'intercom.io': {'service': 'Intercom', 'category': 'functional'},
            'hubspot.com': {'service': 'HubSpot', 'category': 'marketing'},
            'linkedin.com': {'service': 'LinkedIn Insight', 'category': 'marketing'}
        }
        
        # Common cookie patterns and their purposes
        self.cookie_patterns = {
            '_ga': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users'},
            '_gid': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users'},
            '_fbp': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions'},
            '_fbc': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions'},
            'PHPSESSID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality'},
            'JSESSIONID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality'}
        }

    def analyze_website(self, url, progress_callback=None):
        """Analyze a website for compliance issues with improved error handling"""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            domain = urlparse(url).netloc
            
            if progress_callback:
                progress_callback(5, "Initializing website analysis...")
            
            # Try multiple approaches to fetch the website
            response = None
            last_error = None
            
            # Approach 1: Try HTTPS first with retries
            if progress_callback:
                progress_callback(10, "Connecting to website...")
            
            for attempt in range(3):  # 3 attempts
                try:
                    if progress_callback:
                        progress_callback(10 + attempt * 5, f"Fetching website content (attempt {attempt + 1}/3)...")
                    
                    # Configure session with better settings
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1',
                    })
                    
                    # Try with longer timeout and better error handling
                    response = session.get(
                        url, 
                        timeout=(10, 30),  # (connect timeout, read timeout)
                        allow_redirects=True,
                        verify=True,  # Verify SSL certificates
                        stream=False
                    )
                    response.raise_for_status()
                    
                    # If we get here, the request was successful
                    break
                    
                except requests.exceptions.SSLError as e:
                    last_error = f"SSL certificate error: {str(e)}"
                    if attempt == 0:  # Try HTTP on first SSL failure
                        try:
                            http_url = url.replace('https://', 'http://')
                            if progress_callback:
                                progress_callback(15, "Trying HTTP connection...")
                            response = session.get(
                                http_url, 
                                timeout=(10, 30),
                                allow_redirects=True,
                                stream=False
                            )
                            response.raise_for_status()
                            url = http_url  # Update URL for further processing
                            break
                        except Exception:
                            pass  # Continue with retry loop
                            
                except requests.exceptions.Timeout as e:
                    last_error = f"Connection timeout: {str(e)}"
                    time.sleep(2)  # Wait before retry
                    
                except requests.exceptions.ConnectionError as e:
                    last_error = f"Connection error: {str(e)}"
                    time.sleep(2)  # Wait before retry
                    
                except requests.exceptions.RequestException as e:
                    last_error = f"Request error: {str(e)}"
                    time.sleep(1)  # Wait before retry
                    
                except Exception as e:
                    last_error = f"Unexpected error: {str(e)}"
                    break  # Don't retry on unexpected errors
            
            # If all attempts failed
            if response is None:
                raise Exception(f"Failed to fetch website after 3 attempts. Last error: {last_error}")
            
            if progress_callback:
                progress_callback(25, "Website fetched successfully, analyzing content...")
            
            # Validate response
            if len(response.content) == 0:
                raise Exception("Website returned empty content")
            
            if progress_callback:
                progress_callback(30, "Analyzing website structure...")
            
            # Parse HTML if BeautifulSoup is available
            if BS4_AVAILABLE:
                try:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    scripts = self._analyze_scripts(soup, domain)
                    consent_banner = self._check_consent_banner(soup)
                    privacy_policy = self._check_privacy_policy(soup, url)
                except Exception as e:
                    # Fallback to text analysis if HTML parsing fails
                    scripts = self._analyze_scripts_fallback(response.text, domain)
                    consent_banner = self._check_consent_banner_fallback(response.text)
                    privacy_policy = self._check_privacy_policy_fallback(response.text)
            else:
                # Fallback analysis without BeautifulSoup
                scripts = self._analyze_scripts_fallback(response.text, domain)
                consent_banner = self._check_consent_banner_fallback(response.text)
                privacy_policy = self._check_privacy_policy_fallback(response.text)
            
            if progress_callback:
                progress_callback(50, "Detecting cookies and tracking scripts...")
            
            # Analyze cookies
            cookies = self._analyze_cookies(response, domain)
            
            if progress_callback:
                progress_callback(70, "Checking compliance requirements...")
            
            # Generate compliance report
            issues = self._generate_compliance_issues(cookies, scripts, consent_banner, privacy_policy, domain)
            compliance_score = self._calculate_compliance_score(issues)
            
            if progress_callback:
                progress_callback(90, "Generating compliance report...")
            
            # Add some additional analysis time for realism
            time.sleep(1)
            
            if progress_callback:
                progress_callback(100, "Analysis complete!")
            
            return {
                'scan_id': f'real_{int(time.time())}',
                'url': url,
                'domain': domain,
                'status': 'completed',
                'progress': 100,
                'compliance_score': compliance_score,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'issues': issues,
                'cookies': cookies,
                'scripts': scripts,
                'consent_banner': consent_banner,
                'privacy_policy': privacy_policy,
                'potential_earnings': max(100, compliance_score * 10),
                'annual_earnings': max(1200, compliance_score * 120),
                'compliance_breakdown': self._get_compliance_breakdown(issues),
                'recommendations': [
                    'Implement CookieBot.ai for instant GDPR compliance',
                    'Start earning revenue from your consent banner today',
                    'Reduce legal risk with proper cookie categorization',
                    'Get 60% revenue share from affiliate partnerships'
                ]
            }
            
        except requests.RequestException as e:
            # More specific error messages for different types of request errors
            if "Connection aborted" in str(e) or "RemoteDisconnected" in str(e):
                raise Exception(f"Website connection was interrupted. This can happen if the website is slow to respond or blocks automated requests. Please try again or contact the website administrator.")
            elif "timeout" in str(e).lower():
                raise Exception(f"Website took too long to respond (timeout). The website might be slow or temporarily unavailable.")
            elif "ssl" in str(e).lower():
                raise Exception(f"SSL/HTTPS connection error. The website might have certificate issues.")
            else:
                raise Exception(f"Failed to fetch website: {str(e)}")
        except Exception as e:
            if "timeout" in str(e).lower():
                raise Exception(f"Website analysis timed out. The website might be slow or temporarily unavailable.")
            else:
                raise Exception(f"Analysis failed: {str(e)}")

    def _analyze_cookies(self, response, domain):
        """Analyze cookies set by the website"""
        cookies = []
        
        for cookie in response.cookies:
            cookie_info = {
                'name': cookie.name,
                'domain': cookie.domain or domain,
                'secure': cookie.secure,
                'http_only': hasattr(cookie, 'httponly') and cookie.httponly,
                'category': 'unknown',
                'purpose': 'Unknown purpose'
            }
            
            # Categorize cookie based on name patterns
            for pattern, info in self.cookie_patterns.items():
                if pattern in cookie.name.lower():
                    cookie_info['category'] = info['category']
                    cookie_info['purpose'] = info['purpose']
                    break
            
            cookies.append(cookie_info)
        
        return cookies

    def _analyze_scripts(self, soup, domain):
        """Analyze external scripts for tracking services (with BeautifulSoup)"""
        scripts = []
        
        # Find all script tags
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags:
            src = script.get('src', '')
            if src:
                script_info = self._categorize_script(src, domain)
                if script_info['tracking_service'] != 'unknown':
                    scripts.append(script_info)
        
        return scripts

    def _analyze_scripts_fallback(self, html_content, domain):
        """Analyze scripts without BeautifulSoup (fallback)"""
        scripts = []
        
        # Use regex to find script tags
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        
        for src in matches:
            script_info = self._categorize_script(src, domain)
            if script_info['tracking_service'] != 'unknown':
                scripts.append(script_info)
        
        return scripts

    def _categorize_script(self, src, domain):
        """Categorize a script based on its source"""
        # Make relative URLs absolute
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = f"https://{domain}" + src
        
        script_info = {
            'type': 'external',
            'src': src,
            'tracking_service': 'unknown',
            'category': 'unknown',
            'consent_gated': False
        }
        
        # Check if it's a known tracking service
        for tracker_domain, info in self.tracking_scripts.items():
            if tracker_domain in src:
                script_info['tracking_service'] = info['service']
                script_info['category'] = info['category']
                break
        
        return script_info

    def _check_consent_banner(self, soup):
        """Check for cookie consent banner (with BeautifulSoup)"""
        consent_indicators = ['cookie', 'consent', 'privacy', 'gdpr', 'accept']
        
        # Check for common consent banner elements
        for element in soup.find_all(['div', 'section', 'aside']):
            classes = ' '.join(element.get('class', [])).lower()
            element_id = element.get('id', '').lower()
            text_content = element.get_text().lower()
            
            if any(indicator in classes or indicator in element_id or indicator in text_content 
                   for indicator in consent_indicators):
                return {'present': True, 'type': 'detected', 'compliant': True}
        
        return {'present': False, 'type': 'none', 'compliant': False}

    def _check_consent_banner_fallback(self, html_content):
        """Check for consent banner without BeautifulSoup (fallback)"""
        consent_indicators = ['cookie', 'consent', 'privacy', 'gdpr', 'accept']
        html_lower = html_content.lower()
        
        if any(indicator in html_lower for indicator in consent_indicators):
            return {'present': True, 'type': 'detected', 'compliant': True}
        
        return {'present': False, 'type': 'none', 'compliant': False}

    def _check_privacy_policy(self, soup, base_url):
        """Check for privacy policy link (with BeautifulSoup)"""
        privacy_indicators = ['privacy', 'policy', 'legal']
        privacy_links = []
        
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower()
            link_href = link.get('href', '').lower()
            
            if any(indicator in link_text or indicator in link_href for indicator in privacy_indicators):
                privacy_links.append({
                    'text': link.get_text().strip(),
                    'href': urljoin(base_url, link.get('href'))
                })
        
        return {
            'links_found': len(privacy_links),
            'links': privacy_links[:3],
            'accessible': len(privacy_links) > 0
        }

    def _check_privacy_policy_fallback(self, html_content):
        """Check for privacy policy without BeautifulSoup (fallback)"""
        privacy_indicators = ['privacy policy', 'privacy', 'legal']
        html_lower = html_content.lower()
        
        found_count = sum(1 for indicator in privacy_indicators if indicator in html_lower)
        
        return {
            'links_found': found_count,
            'links': [],
            'accessible': found_count > 0
        }

    def _generate_compliance_issues(self, cookies, scripts, consent_banner, privacy_policy, domain):
        """Generate compliance issues based on analysis"""
        issues = []
        
        # Check for consent banner
        if not consent_banner['present']:
            issues.append({
                'type': 'missing_consent_banner',
                'severity': 'critical',
                'title': 'Missing Cookie Consent Banner',
                'description': 'No cookie consent banner was detected on the website.',
                'recommendation': 'Implement a GDPR-compliant cookie consent banner.',
                'regulation': 'gdpr',
                'article': 'Article 7'
            })
        
        # Check for tracking without consent
        tracking_scripts = [s for s in scripts if s['category'] in ['statistics', 'marketing']]
        if tracking_scripts and not consent_banner['present']:
            issues.append({
                'type': 'tracking_without_consent',
                'severity': 'critical',
                'title': 'Tracking Scripts Loading Without Consent',
                'description': f'Found {len(tracking_scripts)} tracking scripts that may load without user consent.',
                'recommendation': 'Ensure all non-essential cookies and tracking scripts are only loaded after explicit user consent.',
                'regulation': 'gdpr',
                'article': 'Article 7'
            })
        
        # Check for privacy policy
        if not privacy_policy['accessible']:
            issues.append({
                'type': 'missing_privacy_policy',
                'severity': 'high',
                'title': 'Privacy Policy Not Easily Accessible',
                'description': 'Privacy policy link is not prominently displayed or accessible.',
                'recommendation': 'Add a clearly visible privacy policy link.',
                'regulation': 'gdpr',
                'article': 'Article 13'
            })
        
        return issues

    def _calculate_compliance_score(self, issues):
        """Calculate compliance score based on issues found"""
        base_score = 100
        
        for issue in issues:
            if issue['severity'] == 'critical':
                base_score -= 25
            elif issue['severity'] == 'high':
                base_score -= 15
            elif issue['severity'] == 'medium':
                base_score -= 10
            elif issue['severity'] == 'low':
                base_score -= 5
        
        return max(0, base_score)

    def _get_compliance_breakdown(self, issues):
        """Get compliance breakdown by regulation"""
        gdpr_issues = len([i for i in issues if i['regulation'] == 'gdpr'])
        
        return {
            'gdpr': {
                'score': max(0, 100 - (gdpr_issues * 20)),
                'issues': gdpr_issues,
                'status': 'compliant' if gdpr_issues == 0 else 'non-compliant'
            },
            'ccpa': {
                'score': max(0, 100 - (gdpr_issues * 15)),
                'issues': max(0, gdpr_issues - 1),
                'status': 'compliant' if gdpr_issues <= 1 else 'partially-compliant'
            },
            'lgpd': {
                'score': max(0, 100 - (gdpr_issues * 20)),
                'issues': gdpr_issues,
                'status': 'compliant' if gdpr_issues == 0 else 'non-compliant'
            }
        }

# Global variables for scan tracking
active_scans = {}
real_analyzer = RealWebsiteAnalyzer()

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        company_name = data.get('company_name', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO users (email, password_hash, company_name) VALUES (%s, %s, %s) RETURNING id',
                (email, password_hash, company_name)
            )
            user_id = cur.fetchone()['id']
            conn.commit()
            
            # Create access token (convert user_id to string for JWT compatibility)
            access_token = create_access_token(identity=str(user_id))
            
            return jsonify({
                'message': 'User registered successfully',
                'access_token': access_token,
                'user': {
                    'id': user_id,
                    'email': email,
                    'company_name': company_name
                }
            }), 201
            
        except psycopg2.IntegrityError:
            return jsonify({'error': 'Email already exists'}), 409
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

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
            cur.execute('SELECT id, password_hash, company_name FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            
            if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Create access token (convert user_id to string for JWT compatibility)
            access_token = create_access_token(identity=str(user['id']))
            
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token,
                'user': {
                    'id': user['id'],
                    'email': email,
                    'company_name': user['company_name']
                }
            }), 200
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

# User profile routes - MISSING ENDPOINT ADDED HERE
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get user profile - This was the missing endpoint causing login issues"""
    try:
        user_id_str = get_jwt_identity()  # This returns a string now
        user_id = int(user_id_str)  # Convert back to integer for database query
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute('SELECT id, email, company_name, created_at FROM users WHERE id = %s', (user_id,))
            user = cur.fetchone()
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'company_name': user['company_name'],
                    'created_at': user['created_at'].isoformat() if user['created_at'] else None
                }
            }), 200
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({'error': 'Failed to get user profile'}), 500

# Dashboard routes
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get website count
            cur.execute('SELECT COUNT(*) as count FROM websites WHERE user_id = %s', (user_id,))
            website_count = cur.fetchone()['count']
            
            # Get total visitors today
            cur.execute('SELECT COALESCE(SUM(visitors_today), 0) as total FROM websites WHERE user_id = %s', (user_id,))
            total_visitors = cur.fetchone()['total']
            
            # Get total revenue today
            cur.execute('SELECT COALESCE(SUM(revenue_today), 0) as total FROM websites WHERE user_id = %s', (user_id,))
            total_revenue = float(cur.fetchone()['total'])
            
            # Get average consent rate
            cur.execute('SELECT COALESCE(AVG(consent_rate), 0) as avg_rate FROM websites WHERE user_id = %s', (user_id,))
            avg_consent_rate = float(cur.fetchone()['avg_rate'])
            
            return jsonify({
                'websites': website_count,
                'visitors_today': total_visitors,
                'revenue_today': total_revenue,
                'consent_rate': round(avg_consent_rate, 2)
            }), 200
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to fetch dashboard stats'}), 500

@app.route('/api/dashboard/websites', methods=['GET'])
@jwt_required()
def get_websites():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute('''
                SELECT id, domain, status, visitors_today, consent_rate, revenue_today, created_at
                FROM websites 
                WHERE user_id = %s 
                ORDER BY created_at DESC
            ''', (user_id,))
            
            websites = cur.fetchall()
            
            # Convert to list of dicts and format
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
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Get websites error: {e}")
        return jsonify({'error': 'Failed to fetch websites'}), 500

@app.route('/api/dashboard/websites', methods=['POST'])
@jwt_required()
def add_website():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Remove protocol if present
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Generate integration code
            integration_code = f"<script src='https://cookiebot.ai/widget/{uuid.uuid4().hex[:16]}.js'></script>"
            
            cur.execute('''
                INSERT INTO websites (user_id, domain, integration_code) 
                VALUES (%s, %s, %s) 
                RETURNING id, domain, status, created_at
            ''', (user_id, domain, integration_code))
            
            website = cur.fetchone()
            conn.commit()
            
            return jsonify({
                'message': 'Website added successfully',
                'website': {
                    'id': website['id'],
                    'domain': website['domain'],
                    'status': website['status'],
                    'visitors_today': 0,
                    'consent_rate': 0.0,
                    'revenue_today': 0.0,
                    'created_at': website['created_at'].isoformat()
                }
            }), 201
            
        except psycopg2.IntegrityError:
            return jsonify({'error': 'Website already exists'}), 409
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Add website error: {e}")
        return jsonify({'error': 'Failed to add website'}), 500

@app.route('/api/dashboard/analytics', methods=['GET'])
@jwt_required()
def get_analytics():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get recent analytics events
            cur.execute('''
                SELECT ae.event_type, ae.consent_given, ae.revenue_generated, ae.created_at, w.domain
                FROM analytics_events ae
                JOIN websites w ON ae.website_id = w.id
                WHERE w.user_id = %s
                ORDER BY ae.created_at DESC
                LIMIT 100
            ''', (user_id,))
            
            events = cur.fetchall()
            
            # Convert to list of dicts
            events_list = []
            for event in events:
                events_list.append({
                    'event_type': event['event_type'],
                    'consent_given': event['consent_given'],
                    'revenue_generated': float(event['revenue_generated']),
                    'domain': event['domain'],
                    'created_at': event['created_at'].isoformat() if event['created_at'] else None
                })
            
            return jsonify({'events': events_list}), 200
            
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Get analytics error: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'auth': ['/api/auth/register', '/api/auth/login'],
            'user': ['/api/user/profile'],
            'dashboard': ['/api/dashboard/stats', '/api/dashboard/websites', '/api/dashboard/analytics'],
            'compliance': ['/api/compliance/demo-scan', '/api/compliance/real-scan', '/api/compliance/health']
        }
    }), 200

# Compliance scanning routes
@app.route('/api/compliance/demo-scan', methods=['POST'])
def demo_compliance_scan():
    """Demo compliance scan endpoint that returns realistic but fast results"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        email = data.get('email', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Generate realistic demo results
        demo_results = {
            'scan_id': 'demo_' + str(int(datetime.utcnow().timestamp())),
            'url': url,
            'domain': domain,
            'status': 'completed',
            'progress': 100,
            'compliance_score': 45,  # Intentionally low to show need for improvement
            'scan_completed_at': datetime.utcnow().isoformat(),
            'issues': [
                {
                    'type': 'missing_consent_banner',
                    'severity': 'critical',
                    'title': 'Missing Cookie Consent Banner',
                    'description': 'No cookie consent banner was detected on the website.',
                    'recommendation': 'Implement a GDPR-compliant cookie consent banner.',
                    'regulation': 'gdpr',
                    'article': 'Article 7'
                },
                {
                    'type': 'tracking_without_consent',
                    'severity': 'critical',
                    'title': 'Tracking Scripts Loading Without Consent',
                    'description': 'Found tracking scripts that may load without user consent.',
                    'recommendation': 'Ensure all non-essential cookies and tracking scripts are only loaded after explicit user consent.',
                    'regulation': 'gdpr',
                    'article': 'Article 7'
                },
                {
                    'type': 'missing_privacy_policy',
                    'severity': 'high',
                    'title': 'Privacy Policy Not Easily Accessible',
                    'description': 'Privacy policy link is not prominently displayed.',
                    'recommendation': 'Add a clearly visible privacy policy link.',
                    'regulation': 'gdpr',
                    'article': 'Article 13'
                },
                {
                    'type': 'cookie_categorization',
                    'severity': 'medium',
                    'title': 'Improper Cookie Categorization',
                    'description': 'Cookies are not properly categorized by purpose.',
                    'recommendation': 'Categorize all cookies as necessary, statistics, marketing, or preferences.',
                    'regulation': 'gdpr',
                    'article': 'Article 7'
                }
            ],
            'cookies': [
                {
                    'name': '_ga',
                    'category': 'statistics',
                    'purpose': 'Google Analytics - Used to distinguish users',
                    'domain': domain,
                    'secure': False,
                    'http_only': False
                },
                {
                    'name': '_gid',
                    'category': 'statistics',
                    'purpose': 'Google Analytics - Used to distinguish users',
                    'domain': domain,
                    'secure': False,
                    'http_only': False
                },
                {
                    'name': '_fbp',
                    'category': 'marketing',
                    'purpose': 'Facebook Pixel - Used to track conversions',
                    'domain': domain,
                    'secure': False,
                    'http_only': False
                },
                {
                    'name': 'PHPSESSID',
                    'category': 'necessary',
                    'purpose': 'Session management - Required for website functionality',
                    'domain': domain,
                    'secure': False,
                    'http_only': True
                }
            ],
            'scripts': [
                {
                    'type': 'external',
                    'src': 'https://www.googletagmanager.com/gtag/js',
                    'tracking_service': 'google-analytics',
                    'consent_gated': False
                },
                {
                    'type': 'external',
                    'src': 'https://connect.facebook.net/en_US/fbevents.js',
                    'tracking_service': 'facebook-pixel',
                    'consent_gated': False
                }
            ],
            'potential_earnings': 450,  # Monthly earning potential
            'annual_earnings': 5400,   # Annual earning potential
            'recommendations': [
                'Implement CookieBot.ai for instant GDPR compliance',
                'Start earning revenue from your consent banner today',
                'Reduce legal risk with proper cookie categorization',
                'Get 60% revenue share from affiliate partnerships'
            ],
            'compliance_breakdown': {
                'gdpr': {
                    'score': 40,
                    'issues': 3,
                    'status': 'non-compliant'
                },
                'ccpa': {
                    'score': 50,
                    'issues': 2,
                    'status': 'partially-compliant'
                },
                'lgpd': {
                    'score': 45,
                    'issues': 2,
                    'status': 'non-compliant'
                }
            }
        }
        
        return jsonify(demo_results), 200
        
    except Exception as e:
        logger.error(f"Error in demo scan: {e}")
        return jsonify({'error': 'Demo scan failed'}), 500

@app.route('/api/compliance/real-scan', methods=['POST'])
def start_real_compliance_scan():
    """Start a real compliance scan that actually analyzes the website"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        email = data.get('email', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Generate scan ID
        scan_id = f'real_{int(time.time())}_{hash(url) % 10000}'
        
        # Initialize scan status
        active_scans[scan_id] = {
            'status': 'pending',
            'progress': 0,
            'message': 'Initializing scan...',
            'url': url,
            'email': email,
            'started_at': datetime.utcnow().isoformat(),
            'results': None
        }
        
        # Start scan in background thread
        def run_scan():
            try:
                def progress_callback(progress, message):
                    if scan_id in active_scans:
                        active_scans[scan_id]['progress'] = progress
                        active_scans[scan_id]['message'] = message
                
                active_scans[scan_id]['status'] = 'running'
                results = real_analyzer.analyze_website(url, progress_callback)
                
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'completed'
                    active_scans[scan_id]['results'] = results
                    active_scans[scan_id]['completed_at'] = datetime.utcnow().isoformat()
                
            except Exception as e:
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'failed'
                    active_scans[scan_id]['error'] = str(e)
                logger.error(f"Real scan failed for {url}: {e}")
        
        # Start scan thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Real compliance scan started. This may take 30-60 seconds.',
            'estimated_time': '30-60 seconds'
        }), 200
        
    except Exception as e:
        logger.error(f"Error starting real scan: {e}")
        return jsonify({'error': 'Failed to start scan'}), 500

@app.route('/api/compliance/real-scan/<scan_id>/status', methods=['GET'])
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
            'message': scan_data['message'],
            'url': scan_data['url']
        }
        
        if scan_data['status'] == 'completed' and scan_data['results']:
            response['results'] = scan_data['results']
        elif scan_data['status'] == 'failed':
            response['error'] = scan_data.get('error', 'Scan failed')
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': 'Failed to get scan status'}), 500

@app.route('/api/compliance/health', methods=['GET'])
def compliance_health_check():
    """Health check endpoint for compliance scanner"""
    return jsonify({
        'status': 'healthy',
        'service': 'compliance-scanner',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

