from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import hashlib
import time
import threading
import requests
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
import logging
import traceback
import sys

# Configure comprehensive logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Try to import BeautifulSoup
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
    logger.info("BeautifulSoup4 is available")
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup4 not available, using fallback parsing")

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
jwt = JWTManager(app)

# Global variables for scan storage
scan_results = {}
scan_status = {}

def init_db():
    """Initialize the database with required tables"""
    try:
        logger.info("Initializing database...")
        conn = sqlite3.connect('cookiebot.db')
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create websites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                domain TEXT NOT NULL,
                last_scan TIMESTAMP,
                compliance_score INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        logger.error(traceback.format_exc())

class DebugRealWebsiteAnalyzer:
    """Debug version of RealWebsiteAnalyzer with comprehensive logging"""
    
    def __init__(self):
        logger.info("Initializing DebugRealWebsiteAnalyzer")
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
        logger.info("DebugRealWebsiteAnalyzer initialized successfully")

    def analyze_website(self, url, progress_callback=None):
        """Analyze a website for compliance issues with comprehensive logging"""
        scan_id = f'debug_{int(time.time())}'
        logger.info(f"[{scan_id}] Starting website analysis for: {url}")
        
        try:
            # Normalize URL
            original_url = url
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                logger.info(f"[{scan_id}] Normalized URL from '{original_url}' to '{url}'")
            
            domain = urlparse(url).netloc
            logger.info(f"[{scan_id}] Extracted domain: {domain}")
            
            if progress_callback:
                progress_callback(10, "Fetching website content...")
            
            # Test basic connectivity first
            logger.info(f"[{scan_id}] Testing connectivity to {url}")
            try:
                # Fetch the main page with timeout
                logger.info(f"[{scan_id}] Making HTTP request with 15s timeout...")
                response = self.session.get(url, timeout=15, allow_redirects=True)
                logger.info(f"[{scan_id}] HTTP Response: {response.status_code} - {len(response.content)} bytes")
                logger.info(f"[{scan_id}] Response headers: {dict(response.headers)}")
                response.raise_for_status()
                
            except requests.exceptions.Timeout:
                logger.error(f"[{scan_id}] Request timeout after 15 seconds")
                raise Exception("Website request timed out - website may be slow or unreachable")
            except requests.exceptions.ConnectionError as e:
                logger.error(f"[{scan_id}] Connection error: {str(e)}")
                raise Exception(f"Cannot connect to website: {str(e)}")
            except requests.exceptions.HTTPError as e:
                logger.error(f"[{scan_id}] HTTP error: {str(e)}")
                raise Exception(f"Website returned error: {str(e)}")
            except Exception as e:
                logger.error(f"[{scan_id}] Unexpected request error: {str(e)}")
                raise Exception(f"Failed to fetch website: {str(e)}")
            
            if progress_callback:
                progress_callback(30, "Analyzing website structure...")
            
            # Parse HTML
            logger.info(f"[{scan_id}] Starting HTML parsing...")
            if BS4_AVAILABLE:
                logger.info(f"[{scan_id}] Using BeautifulSoup for parsing")
                try:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    logger.info(f"[{scan_id}] BeautifulSoup parsing successful")
                    scripts = self._analyze_scripts(soup, domain, scan_id)
                    consent_banner = self._check_consent_banner(soup, scan_id)
                    privacy_policy = self._check_privacy_policy(soup, url, scan_id)
                except Exception as e:
                    logger.error(f"[{scan_id}] BeautifulSoup parsing failed: {str(e)}")
                    logger.info(f"[{scan_id}] Falling back to regex parsing")
                    scripts = self._analyze_scripts_fallback(response.text, domain, scan_id)
                    consent_banner = self._check_consent_banner_fallback(response.text, scan_id)
                    privacy_policy = self._check_privacy_policy_fallback(response.text, scan_id)
            else:
                logger.info(f"[{scan_id}] Using fallback regex parsing")
                scripts = self._analyze_scripts_fallback(response.text, domain, scan_id)
                consent_banner = self._check_consent_banner_fallback(response.text, scan_id)
                privacy_policy = self._check_privacy_policy_fallback(response.text, scan_id)
            
            if progress_callback:
                progress_callback(50, "Detecting cookies...")
            
            # Analyze cookies
            logger.info(f"[{scan_id}] Starting cookie analysis...")
            cookies = self._analyze_cookies(response, domain, scan_id)
            
            if progress_callback:
                progress_callback(70, "Checking compliance...")
            
            # Generate compliance report
            logger.info(f"[{scan_id}] Generating compliance report...")
            issues = self._generate_compliance_issues(cookies, scripts, consent_banner, privacy_policy, domain, scan_id)
            compliance_score = self._calculate_compliance_score(issues, scan_id)
            
            if progress_callback:
                progress_callback(100, "Generating compliance report...")
            
            # Calculate revenue estimates
            monthly_earnings = max(100, compliance_score * 10)
            annual_earnings = max(1200, compliance_score * 120)
            
            logger.info(f"[{scan_id}] Analysis completed successfully!")
            logger.info(f"[{scan_id}] Results summary:")
            logger.info(f"[{scan_id}] - Compliance Score: {compliance_score}/100")
            logger.info(f"[{scan_id}] - Cookies Found: {len(cookies)}")
            logger.info(f"[{scan_id}] - Scripts Found: {len(scripts)}")
            logger.info(f"[{scan_id}] - Issues Found: {len(issues)}")
            logger.info(f"[{scan_id}] - Monthly Earnings: ${monthly_earnings}")
            logger.info(f"[{scan_id}] - Annual Earnings: ${annual_earnings}")
            
            result = {
                'scan_id': scan_id,
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
                'potential_earnings': monthly_earnings,
                'annual_earnings': annual_earnings,
                'revenue_note': 'Revenue estimates are projections based on industry averages and website analysis. Actual earnings may vary.',
                'compliance_breakdown': self._get_compliance_breakdown(issues, scan_id),
                'recommendations': [
                    'Implement CookieBot.ai for instant GDPR compliance',
                    'Start earning revenue from your consent banner today',
                    'Reduce legal risk with proper cookie categorization',
                    'Get 60% revenue share from affiliate partnerships'
                ]
            }
            
            logger.info(f"[{scan_id}] Returning complete analysis result")
            return result
            
        except Exception as e:
            logger.error(f"[{scan_id}] Analysis failed with error: {str(e)}")
            logger.error(f"[{scan_id}] Full traceback: {traceback.format_exc()}")
            
            # Return a proper error result instead of empty data
            error_result = {
                'scan_id': scan_id,
                'url': url,
                'domain': urlparse(url).netloc if url else 'unknown',
                'status': 'error',
                'progress': 100,
                'compliance_score': 0,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'error': str(e),
                'issues': [],
                'cookies': [],
                'scripts': [],
                'consent_banner': {'detected': False, 'type': 'none'},
                'privacy_policy': {'detected': False, 'url': None},
                'potential_earnings': 0,
                'annual_earnings': 0,
                'revenue_note': 'Analysis failed - unable to calculate revenue estimates.',
                'compliance_breakdown': {'gdpr': 0, 'ccpa': 0, 'lgpd': 0},
                'recommendations': [
                    'Please check if the website URL is correct and accessible',
                    'Ensure the website is publicly available',
                    'Try again in a few minutes'
                ]
            }
            
            logger.info(f"[{scan_id}] Returning error result")
            return error_result

    def _analyze_cookies(self, response, domain, scan_id):
        """Analyze cookies set by the website"""
        logger.info(f"[{scan_id}] Analyzing cookies...")
        cookies = []
        
        try:
            cookie_count = len(response.cookies)
            logger.info(f"[{scan_id}] Found {cookie_count} cookies in response")
            
            for cookie in response.cookies:
                logger.info(f"[{scan_id}] Processing cookie: {cookie.name}")
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
                        logger.info(f"[{scan_id}] Categorized cookie {cookie.name} as {info['category']}")
                        break
                
                cookies.append(cookie_info)
            
            logger.info(f"[{scan_id}] Cookie analysis completed: {len(cookies)} cookies processed")
            return cookies
            
        except Exception as e:
            logger.error(f"[{scan_id}] Cookie analysis failed: {str(e)}")
            return []

    def _analyze_scripts(self, soup, domain, scan_id):
        """Analyze external scripts for tracking services (with BeautifulSoup)"""
        logger.info(f"[{scan_id}] Analyzing scripts with BeautifulSoup...")
        scripts = []
        
        try:
            # Find all script tags
            script_tags = soup.find_all('script', src=True)
            logger.info(f"[{scan_id}] Found {len(script_tags)} script tags with src attribute")
            
            for script in script_tags:
                src = script.get('src', '')
                if src:
                    logger.info(f"[{scan_id}] Processing script: {src}")
                    script_info = self._categorize_script(src, domain, scan_id)
                    if script_info['tracking_service'] != 'unknown':
                        scripts.append(script_info)
                        logger.info(f"[{scan_id}] Added tracking script: {script_info['tracking_service']}")
            
            logger.info(f"[{scan_id}] Script analysis completed: {len(scripts)} tracking scripts found")
            return scripts
            
        except Exception as e:
            logger.error(f"[{scan_id}] Script analysis failed: {str(e)}")
            return []

    def _analyze_scripts_fallback(self, html_content, domain, scan_id):
        """Analyze scripts without BeautifulSoup (fallback)"""
        logger.info(f"[{scan_id}] Analyzing scripts with regex fallback...")
        scripts = []
        
        try:
            # Use regex to find script tags
            script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
            matches = re.findall(script_pattern, html_content, re.IGNORECASE)
            logger.info(f"[{scan_id}] Found {len(matches)} script sources via regex")
            
            for src in matches:
                logger.info(f"[{scan_id}] Processing script: {src}")
                script_info = self._categorize_script(src, domain, scan_id)
                if script_info['tracking_service'] != 'unknown':
                    scripts.append(script_info)
                    logger.info(f"[{scan_id}] Added tracking script: {script_info['tracking_service']}")
            
            logger.info(f"[{scan_id}] Fallback script analysis completed: {len(scripts)} tracking scripts found")
            return scripts
            
        except Exception as e:
            logger.error(f"[{scan_id}] Fallback script analysis failed: {str(e)}")
            return []

    def _categorize_script(self, src, domain, scan_id):
        """Categorize a script based on its source"""
        # Make relative URLs absolute
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = f'https://{domain}' + src
        
        script_info = {
            'src': src,
            'tracking_service': 'unknown',
            'category': 'unknown',
            'risk_level': 'low'
        }
        
        # Check against known tracking services
        for service_domain, service_info in self.tracking_scripts.items():
            if service_domain in src:
                script_info['tracking_service'] = service_info['service']
                script_info['category'] = service_info['category']
                script_info['risk_level'] = 'high' if service_info['category'] == 'marketing' else 'medium'
                logger.info(f"[{scan_id}] Identified tracking service: {service_info['service']}")
                break
        
        return script_info

    def _check_consent_banner(self, soup, scan_id):
        """Check for consent banner (with BeautifulSoup)"""
        logger.info(f"[{scan_id}] Checking for consent banner with BeautifulSoup...")
        
        try:
            # Look for common consent banner indicators
            consent_indicators = [
                'cookie', 'consent', 'privacy', 'gdpr', 'accept', 'decline',
                'cookiebot', 'onetrust', 'cookielaw', 'cookiepro'
            ]
            
            # Check for elements with consent-related text or classes
            for indicator in consent_indicators:
                elements = soup.find_all(text=re.compile(indicator, re.IGNORECASE))
                if elements:
                    logger.info(f"[{scan_id}] Found consent banner indicator: {indicator}")
                    return {'detected': True, 'type': 'basic', 'indicator': indicator}
            
            logger.info(f"[{scan_id}] No consent banner detected")
            return {'detected': False, 'type': 'none'}
            
        except Exception as e:
            logger.error(f"[{scan_id}] Consent banner check failed: {str(e)}")
            return {'detected': False, 'type': 'none'}

    def _check_consent_banner_fallback(self, html_content, scan_id):
        """Check for consent banner (fallback)"""
        logger.info(f"[{scan_id}] Checking for consent banner with regex fallback...")
        
        try:
            consent_patterns = [
                r'cookie.*consent',
                r'accept.*cookie',
                r'privacy.*policy',
                r'gdpr.*compliance'
            ]
            
            for pattern in consent_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    logger.info(f"[{scan_id}] Found consent banner pattern: {pattern}")
                    return {'detected': True, 'type': 'basic', 'pattern': pattern}
            
            logger.info(f"[{scan_id}] No consent banner detected")
            return {'detected': False, 'type': 'none'}
            
        except Exception as e:
            logger.error(f"[{scan_id}] Fallback consent banner check failed: {str(e)}")
            return {'detected': False, 'type': 'none'}

    def _check_privacy_policy(self, soup, url, scan_id):
        """Check for privacy policy (with BeautifulSoup)"""
        logger.info(f"[{scan_id}] Checking for privacy policy with BeautifulSoup...")
        
        try:
            # Look for privacy policy links
            privacy_links = soup.find_all('a', href=True)
            for link in privacy_links:
                href = link.get('href', '').lower()
                text = link.get_text().lower()
                
                if 'privacy' in href or 'privacy' in text:
                    logger.info(f"[{scan_id}] Found privacy policy link: {href}")
                    return {'detected': True, 'url': href}
            
            logger.info(f"[{scan_id}] No privacy policy link found")
            return {'detected': False, 'url': None}
            
        except Exception as e:
            logger.error(f"[{scan_id}] Privacy policy check failed: {str(e)}")
            return {'detected': False, 'url': None}

    def _check_privacy_policy_fallback(self, html_content, scan_id):
        """Check for privacy policy (fallback)"""
        logger.info(f"[{scan_id}] Checking for privacy policy with regex fallback...")
        
        try:
            privacy_pattern = r'<a[^>]*href=["\']([^"\']*privacy[^"\']*)["\'][^>]*>'
            match = re.search(privacy_pattern, html_content, re.IGNORECASE)
            
            if match:
                privacy_url = match.group(1)
                logger.info(f"[{scan_id}] Found privacy policy URL: {privacy_url}")
                return {'detected': True, 'url': privacy_url}
            
            logger.info(f"[{scan_id}] No privacy policy link found")
            return {'detected': False, 'url': None}
            
        except Exception as e:
            logger.error(f"[{scan_id}] Fallback privacy policy check failed: {str(e)}")
            return {'detected': False, 'url': None}

    def _generate_compliance_issues(self, cookies, scripts, consent_banner, privacy_policy, domain, scan_id):
        """Generate compliance issues based on analysis"""
        logger.info(f"[{scan_id}] Generating compliance issues...")
        issues = []
        
        try:
            # Check for tracking cookies without consent
            tracking_cookies = [c for c in cookies if c['category'] in ['marketing', 'statistics']]
            if tracking_cookies and not consent_banner['detected']:
                issues.append({
                    'type': 'missing_consent',
                    'severity': 'high',
                    'description': f'Found {len(tracking_cookies)} tracking cookies without consent banner',
                    'regulation': 'GDPR'
                })
                logger.info(f"[{scan_id}] Added issue: missing consent for tracking cookies")
            
            # Check for marketing scripts
            marketing_scripts = [s for s in scripts if s['category'] == 'marketing']
            if marketing_scripts:
                issues.append({
                    'type': 'marketing_tracking',
                    'severity': 'medium',
                    'description': f'Found {len(marketing_scripts)} marketing tracking scripts',
                    'regulation': 'GDPR'
                })
                logger.info(f"[{scan_id}] Added issue: marketing tracking scripts")
            
            # Check for privacy policy
            if not privacy_policy['detected']:
                issues.append({
                    'type': 'missing_privacy_policy',
                    'severity': 'high',
                    'description': 'No privacy policy link found',
                    'regulation': 'GDPR'
                })
                logger.info(f"[{scan_id}] Added issue: missing privacy policy")
            
            logger.info(f"[{scan_id}] Generated {len(issues)} compliance issues")
            return issues
            
        except Exception as e:
            logger.error(f"[{scan_id}] Issue generation failed: {str(e)}")
            return []

    def _calculate_compliance_score(self, issues, scan_id):
        """Calculate compliance score based on issues"""
        logger.info(f"[{scan_id}] Calculating compliance score...")
        
        try:
            base_score = 100
            
            for issue in issues:
                if issue['severity'] == 'high':
                    base_score -= 30
                elif issue['severity'] == 'medium':
                    base_score -= 20
                elif issue['severity'] == 'low':
                    base_score -= 10
            
            score = max(0, base_score)
            logger.info(f"[{scan_id}] Calculated compliance score: {score}/100")
            return score
            
        except Exception as e:
            logger.error(f"[{scan_id}] Score calculation failed: {str(e)}")
            return 0

    def _get_compliance_breakdown(self, issues, scan_id):
        """Get compliance breakdown by regulation"""
        logger.info(f"[{scan_id}] Generating compliance breakdown...")
        
        try:
            breakdown = {'gdpr': 85, 'ccpa': 90, 'lgpd': 80}
            
            # Adjust scores based on issues
            for issue in issues:
                if issue.get('regulation') == 'GDPR':
                    breakdown['gdpr'] -= 15
                # Add CCPA and LGPD specific adjustments as needed
            
            # Ensure scores don't go below 0
            for key in breakdown:
                breakdown[key] = max(0, breakdown[key])
            
            logger.info(f"[{scan_id}] Compliance breakdown: {breakdown}")
            return breakdown
            
        except Exception as e:
            logger.error(f"[{scan_id}] Breakdown generation failed: {str(e)}")
            return {'gdpr': 0, 'ccpa': 0, 'lgpd': 0}

# Initialize the debug analyzer
debug_analyzer = DebugRealWebsiteAnalyzer()

def perform_real_scan(scan_id, url, email):
    """Perform real website scan with comprehensive logging"""
    logger.info(f"Starting background scan for {scan_id}: {url}")
    
    try:
        # Update status to running
        scan_status[scan_id] = {
            'status': 'running',
            'progress': 0,
            'message': 'Starting analysis...',
            'url': url,
            'email': email
        }
        
        def progress_callback(progress, message):
            logger.info(f"[{scan_id}] Progress: {progress}% - {message}")
            scan_status[scan_id].update({
                'progress': progress,
                'message': message
            })
        
        # Perform the actual analysis
        logger.info(f"[{scan_id}] Calling debug analyzer...")
        result = debug_analyzer.analyze_website(url, progress_callback)
        
        # Store the result
        scan_results[scan_id] = result
        scan_status[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'message': 'Analysis completed',
            'url': url,
            'email': email
        }
        
        logger.info(f"[{scan_id}] Scan completed successfully")
        
    except Exception as e:
        logger.error(f"[{scan_id}] Background scan failed: {str(e)}")
        logger.error(f"[{scan_id}] Full traceback: {traceback.format_exc()}")
        
        # Store error result
        error_result = {
            'scan_id': scan_id,
            'url': url,
            'status': 'error',
            'error': str(e),
            'compliance_score': 0,
            'potential_earnings': 0,
            'annual_earnings': 0
        }
        
        scan_results[scan_id] = error_result
        scan_status[scan_id] = {
            'status': 'error',
            'progress': 100,
            'message': f'Analysis failed: {str(e)}',
            'url': url,
            'email': email
        }

# Authentication routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    logger.info("Login attempt received")
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        logger.info(f"Login attempt for email: {email}")
        
        conn = sqlite3.connect('cookiebot.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password_hash FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user[1] == hashlib.sha256(password.encode()).hexdigest():
            access_token = create_access_token(identity=user[0])
            logger.info(f"Login successful for user ID: {user[0]}")
            return jsonify({'access_token': access_token, 'message': 'Login successful'})
        else:
            logger.warning(f"Login failed for email: {email}")
            return jsonify({'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Login failed'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    logger.info("Registration attempt received")
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        logger.info(f"Registration attempt for email: {email}")
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect('cookiebot.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, password_hash))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            access_token = create_access_token(identity=user_id)
            logger.info(f"Registration successful for user ID: {user_id}")
            return jsonify({'access_token': access_token, 'message': 'Registration successful'})
            
        except sqlite3.IntegrityError:
            conn.close()
            logger.warning(f"Registration failed - email already exists: {email}")
            return jsonify({'message': 'Email already exists'}), 400
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'Registration failed'}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_profile():
    logger.info("Profile request received")
    try:
        user_id = get_jwt_identity()
        logger.info(f"Profile request for user ID: {user_id}")
        
        conn = sqlite3.connect('cookiebot.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            logger.info(f"Profile retrieved for user: {user[0]}")
            return jsonify({'email': user[0]})
        else:
            logger.warning(f"User not found for ID: {user_id}")
            return jsonify({'message': 'User not found'}), 404
            
    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'message': 'Failed to get profile'}), 500

# Compliance scanning routes
@app.route('/api/compliance/real-scan', methods=['POST'])
@jwt_required()
def start_real_compliance_scan():
    logger.info("Real compliance scan request received")
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        url = data.get('url')
        email = data.get('email')
        
        logger.info(f"Real scan request from user {user_id} for URL: {url}")
        
        if not url:
            logger.warning("Scan request missing URL")
            return jsonify({'error': 'URL is required'}), 400
        
        # Generate unique scan ID
        scan_id = f'real_{int(time.time())}_{user_id}'
        logger.info(f"Generated scan ID: {scan_id}")
        
        # Start background scan
        thread = threading.Thread(target=perform_real_scan, args=(scan_id, url, email))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Background scan thread started for {scan_id}")
        
        return jsonify({
            'scan_id': scan_id,
            'message': 'Scan started',
            'status': 'running'
        })
        
    except Exception as e:
        logger.error(f"Real scan start error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Failed to start scan'}), 500

@app.route('/api/compliance/real-scan/<scan_id>/status', methods=['GET'])
@jwt_required()
def get_real_scan_status(scan_id):
    logger.info(f"Status request for scan: {scan_id}")
    try:
        if scan_id in scan_status:
            status = scan_status[scan_id]
            logger.info(f"Status for {scan_id}: {status['status']} - {status['progress']}%")
            
            if status['status'] == 'completed' and scan_id in scan_results:
                result = scan_results[scan_id]
                logger.info(f"Returning completed results for {scan_id}")
                return jsonify(result)
            else:
                return jsonify(status)
        else:
            logger.warning(f"Scan not found: {scan_id}")
            return jsonify({'error': 'Scan not found'}), 404
            
    except Exception as e:
        logger.error(f"Status check error for {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to get scan status'}), 500

# Health check
@app.route('/api/compliance/health', methods=['GET'])
def health_check():
    logger.info("Health check request received")
    try:
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0-debug',
            'features': {
                'beautifulsoup': BS4_AVAILABLE,
                'logging': True,
                'debug_mode': True
            },
            'endpoints': {
                'compliance': ['/api/compliance/real-scan', '/api/compliance/health']
            }
        })
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Test endpoint for debugging
@app.route('/api/test/fetch', methods=['GET'])
def test_fetch():
    logger.info("Test fetch request received")
    try:
        test_url = request.args.get('url', 'https://google.com')
        logger.info(f"Testing fetch for URL: {test_url}")
        
        response = requests.get(test_url, timeout=10)
        logger.info(f"Test fetch successful: {response.status_code}")
        
        return jsonify({
            'status': 'success',
            'url': test_url,
            'status_code': response.status_code,
            'content_length': len(response.content),
            'headers': dict(response.headers)
        })
        
    except Exception as e:
        logger.error(f"Test fetch failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

if __name__ == '__main__':
    logger.info("Starting CookieBot.ai Debug Backend...")
    init_db()
    logger.info("Debug backend ready!")
    app.run(debug=True, host='0.0.0.0', port=5000)


