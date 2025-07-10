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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Websites table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                url VARCHAR(500) NOT NULL,
                domain VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'active',
                last_scan_at TIMESTAMP,
                compliance_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance scans table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS compliance_scans (
                id SERIAL PRIMARY KEY,
                scan_id VARCHAR(100) UNIQUE NOT NULL,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                url VARCHAR(500) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                compliance_score INTEGER DEFAULT 0,
                results JSONB,
                error_message TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        # Analytics events table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                event_data JSONB,
                visitor_id VARCHAR(100),
                ip_address INET,
                user_agent TEXT,
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
        conn.close()

class EnhancedWebsiteAnalyzer:
    """Enhanced website analyzer with comprehensive GDPR, CCPA, and LGPD compliance checks"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Enhanced tracking scripts database
        self.tracking_scripts = {
            'googletagmanager.com': {'service': 'Google Tag Manager', 'category': 'statistics', 'gdpr_risk': 'high'},
            'google-analytics.com': {'service': 'Google Analytics', 'category': 'statistics', 'gdpr_risk': 'high'},
            'googleadservices.com': {'service': 'Google Ads', 'category': 'marketing', 'gdpr_risk': 'high'},
            'facebook.net': {'service': 'Facebook Pixel', 'category': 'marketing', 'gdpr_risk': 'high'},
            'doubleclick.net': {'service': 'Google DoubleClick', 'category': 'marketing', 'gdpr_risk': 'high'},
            'hotjar.com': {'service': 'Hotjar', 'category': 'statistics', 'gdpr_risk': 'high'},
            'mixpanel.com': {'service': 'Mixpanel', 'category': 'statistics', 'gdpr_risk': 'medium'},
            'intercom.io': {'service': 'Intercom', 'category': 'functional', 'gdpr_risk': 'medium'},
            'hubspot.com': {'service': 'HubSpot', 'category': 'marketing', 'gdpr_risk': 'high'},
            'linkedin.com': {'service': 'LinkedIn Insight', 'category': 'marketing', 'gdpr_risk': 'high'},
            'tiktok.com': {'service': 'TikTok Pixel', 'category': 'marketing', 'gdpr_risk': 'high'},
            'snapchat.com': {'service': 'Snapchat Pixel', 'category': 'marketing', 'gdpr_risk': 'high'},
            'pinterest.com': {'service': 'Pinterest Tag', 'category': 'marketing', 'gdpr_risk': 'high'},
            'twitter.com': {'service': 'Twitter Pixel', 'category': 'marketing', 'gdpr_risk': 'high'},
            'amazon-adsystem.com': {'service': 'Amazon DSP', 'category': 'marketing', 'gdpr_risk': 'high'}
        }
        
        # Enhanced cookie patterns
        self.cookie_patterns = {
            '_ga': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users', 'gdpr_risk': 'high'},
            '_gid': {'category': 'statistics', 'purpose': 'Google Analytics - Used to distinguish users', 'gdpr_risk': 'high'},
            '_fbp': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions', 'gdpr_risk': 'high'},
            '_fbc': {'category': 'marketing', 'purpose': 'Facebook Pixel - Used to track conversions', 'gdpr_risk': 'high'},
            '__utma': {'category': 'statistics', 'purpose': 'Google Analytics - Visitor tracking', 'gdpr_risk': 'high'},
            '__utmb': {'category': 'statistics', 'purpose': 'Google Analytics - Session tracking', 'gdpr_risk': 'high'},
            '__utmc': {'category': 'statistics', 'purpose': 'Google Analytics - Session tracking', 'gdpr_risk': 'high'},
            '__utmz': {'category': 'statistics', 'purpose': 'Google Analytics - Traffic source tracking', 'gdpr_risk': 'high'},
            'PHPSESSID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality', 'gdpr_risk': 'low'},
            'JSESSIONID': {'category': 'necessary', 'purpose': 'Session management - Required for website functionality', 'gdpr_risk': 'low'},
            '_hjid': {'category': 'statistics', 'purpose': 'Hotjar - User identification', 'gdpr_risk': 'high'},
            '_hjSessionUser': {'category': 'statistics', 'purpose': 'Hotjar - Session tracking', 'gdpr_risk': 'high'},
            'intercom-id': {'category': 'functional', 'purpose': 'Intercom - User identification', 'gdpr_risk': 'medium'},
            'hubspotutk': {'category': 'marketing', 'purpose': 'HubSpot - User tracking', 'gdpr_risk': 'high'}
        }

        # Compliance frameworks and their requirements
        self.compliance_frameworks = {
            'gdpr': {
                'name': 'General Data Protection Regulation',
                'region': 'EU',
                'key_requirements': [
                    'explicit_consent',
                    'consent_withdrawal',
                    'privacy_policy',
                    'data_minimization',
                    'purpose_limitation',
                    'cookie_banner'
                ]
            },
            'ccpa': {
                'name': 'California Consumer Privacy Act',
                'region': 'California, US',
                'key_requirements': [
                    'privacy_policy',
                    'do_not_sell_link',
                    'data_disclosure',
                    'opt_out_mechanism'
                ]
            },
            'lgpd': {
                'name': 'Lei Geral de Proteção de Dados',
                'region': 'Brazil',
                'key_requirements': [
                    'explicit_consent',
                    'privacy_policy',
                    'data_minimization',
                    'purpose_limitation'
                ]
            }
        }

    def analyze_website(self, url, progress_callback=None):
        """Comprehensive website analysis for multiple compliance frameworks"""
        try:
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            domain = urlparse(url).netloc
            
            if progress_callback:
                progress_callback(5, "Starting compliance analysis...")
            
            # Enhanced retry logic for better connection handling
            response = self._fetch_website_with_retry(url, progress_callback)
            
            if progress_callback:
                progress_callback(25, "Analyzing website structure...")
            
            # Parse HTML content
            if BS4_AVAILABLE:
                soup = BeautifulSoup(response.content, 'html.parser')
                scripts = self._analyze_scripts(soup, domain)
                consent_banner = self._check_consent_banner(soup)
                privacy_policy = self._check_privacy_policy(soup, url)
                ccpa_compliance = self._check_ccpa_compliance(soup, url)
            else:
                # Fallback analysis without BeautifulSoup
                scripts = self._analyze_scripts_fallback(response.text, domain)
                consent_banner = self._check_consent_banner_fallback(response.text)
                privacy_policy = self._check_privacy_policy_fallback(response.text)
                ccpa_compliance = self._check_ccpa_compliance_fallback(response.text)
            
            if progress_callback:
                progress_callback(50, "Detecting cookies and tracking...")
            
            # Analyze cookies
            cookies = self._analyze_cookies(response, domain)
            
            if progress_callback:
                progress_callback(70, "Evaluating compliance frameworks...")
            
            # Generate comprehensive compliance analysis
            issues = self._generate_enhanced_compliance_issues(
                cookies, scripts, consent_banner, privacy_policy, ccpa_compliance, domain
            )
            
            compliance_breakdown = self._calculate_framework_compliance(issues)
            overall_score = self._calculate_overall_compliance_score(compliance_breakdown)
            
            if progress_callback:
                progress_callback(90, "Calculating revenue potential...")
            
            # Calculate realistic revenue potential (marked as estimates)
            revenue_data = self._calculate_revenue_estimates(overall_score, len(cookies), len(scripts))
            
            if progress_callback:
                progress_callback(100, "Generating compliance report...")
            
            return {
                'scan_id': f'real_{int(time.time())}',
                'url': url,
                'domain': domain,
                'status': 'completed',
                'progress': 100,
                'compliance_score': overall_score,
                'scan_completed_at': datetime.utcnow().isoformat(),
                'issues': issues,
                'cookies': cookies,
                'scripts': scripts,
                'consent_banner': consent_banner,
                'privacy_policy': privacy_policy,
                'ccpa_compliance': ccpa_compliance,
                'compliance_breakdown': compliance_breakdown,
                'potential_earnings': revenue_data['monthly'],
                'annual_earnings': revenue_data['annual'],
                'revenue_note': 'Revenue estimates are projections based on industry averages and website analysis. Actual earnings may vary.',
                'recommendations': self._generate_recommendations(issues, compliance_breakdown)
            }
            
        except Exception as e:
            logger.error(f"Website analysis failed: {str(e)}")
            raise Exception(f"Analysis failed: {str(e)}")

    def _fetch_website_with_retry(self, url, progress_callback=None, max_retries=3):
        """Enhanced website fetching with retry logic and better error handling"""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                if progress_callback and attempt > 0:
                    progress_callback(10 + (attempt * 5), f"Retry attempt {attempt + 1}...")
                
                # Try HTTPS first, then HTTP if it fails
                test_url = url
                if attempt == 1 and url.startswith('https://'):
                    test_url = url.replace('https://', 'http://')
                
                response = self.session.get(
                    test_url, 
                    timeout=(10, 30),  # 10s connect, 30s read
                    allow_redirects=True,
                    verify=True if test_url.startswith('https://') else False
                )
                response.raise_for_status()
                
                # Check if response has content
                if len(response.content) < 100:
                    raise requests.RequestException("Empty or minimal response received")
                
                return response
                
            except requests.exceptions.SSLError as e:
                last_error = f"SSL/HTTPS connection error. The website might have certificate issues."
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                    
            except requests.exceptions.Timeout as e:
                last_error = f"Website took too long to respond (timeout). The website might be slow or temporarily unavailable."
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                    
            except requests.exceptions.ConnectionError as e:
                last_error = f"Website connection was interrupted. This can happen if the website is slow to respond or blocks automated requests."
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                    
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        raise requests.RequestException(last_error)

    def _analyze_cookies(self, response, domain):
        """Enhanced cookie analysis with compliance risk assessment"""
        cookies = []
        
        for cookie in response.cookies:
            cookie_info = {
                'name': cookie.name,
                'domain': cookie.domain or domain,
                'secure': cookie.secure,
                'http_only': hasattr(cookie, 'httponly') and cookie.httponly,
                'category': 'unknown',
                'purpose': 'Unknown purpose',
                'gdpr_risk': 'medium',
                'requires_consent': True
            }
            
            # Enhanced categorization with compliance risk
            for pattern, info in self.cookie_patterns.items():
                if pattern in cookie.name.lower():
                    cookie_info.update(info)
                    break
            
            # Necessary cookies don't require consent
            if cookie_info['category'] == 'necessary':
                cookie_info['requires_consent'] = False
            
            cookies.append(cookie_info)
        
        return cookies

    def _check_consent_banner(self, soup):
        """Enhanced consent banner detection with GDPR compliance checks"""
        consent_indicators = [
            'cookie', 'consent', 'privacy', 'gdpr', 'accept', 'decline', 'reject',
            'necessary', 'analytics', 'marketing', 'functional', 'preferences'
        ]
        
        banner_found = False
        banner_type = 'none'
        has_reject_option = False
        has_granular_controls = False
        
        # Check for common consent banner elements
        for element in soup.find_all(['div', 'section', 'aside'], class_=True):
            class_text = ' '.join(element.get('class', [])).lower()
            element_text = element.get_text().lower()
            
            if any(indicator in class_text or indicator in element_text for indicator in consent_indicators):
                banner_found = True
                
                # Check for reject/decline options
                if any(word in element_text for word in ['reject', 'decline', 'deny', 'refuse']):
                    has_reject_option = True
                
                # Check for granular controls
                if any(word in element_text for word in ['necessary', 'analytics', 'marketing', 'functional', 'customize', 'settings']):
                    has_granular_controls = True
                
                # Determine banner type
                if has_reject_option and has_granular_controls:
                    banner_type = 'compliant'
                elif has_reject_option:
                    banner_type = 'basic'
                else:
                    banner_type = 'non_compliant'
                break
        
        return {
            'found': banner_found,
            'type': banner_type,
            'has_reject_option': has_reject_option,
            'has_granular_controls': has_granular_controls,
            'gdpr_compliant': banner_type == 'compliant'
        }

    def _check_privacy_policy(self, soup, base_url):
        """Enhanced privacy policy detection and analysis"""
        privacy_indicators = ['privacy policy', 'privacy notice', 'data protection', 'cookie policy']
        
        policy_found = False
        policy_url = None
        easily_accessible = False
        
        # Check for privacy policy links
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower()
            if any(indicator in link_text for indicator in privacy_indicators):
                policy_found = True
                policy_url = urljoin(base_url, link.get('href'))
                
                # Check if link is in footer (easily accessible)
                parent_elements = [p.name for p in link.parents]
                if 'footer' in parent_elements:
                    easily_accessible = True
                break
        
        return {
            'found': policy_found,
            'url': policy_url,
            'easily_accessible': easily_accessible,
            'gdpr_compliant': policy_found and easily_accessible
        }

    def _check_ccpa_compliance(self, soup, base_url):
        """Check for CCPA-specific compliance elements"""
        ccpa_indicators = [
            'do not sell', 'do not sell my personal information', 'ccpa', 
            'california privacy', 'opt out', 'your privacy choices'
        ]
        
        do_not_sell_found = False
        do_not_sell_url = None
        
        # Check for "Do Not Sell" links
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower()
            if any(indicator in link_text for indicator in ccpa_indicators):
                do_not_sell_found = True
                do_not_sell_url = urljoin(base_url, link.get('href'))
                break
        
        return {
            'do_not_sell_found': do_not_sell_found,
            'do_not_sell_url': do_not_sell_url,
            'ccpa_compliant': do_not_sell_found
        }

    def _generate_enhanced_compliance_issues(self, cookies, scripts, consent_banner, privacy_policy, ccpa_compliance, domain):
        """Generate comprehensive compliance issues for all frameworks"""
        issues = []
        
        # GDPR Issues
        if not consent_banner['found']:
            issues.append({
                'type': 'missing_consent_banner',
                'severity': 'critical',
                'title': 'Missing Cookie Consent Banner',
                'description': 'No cookie consent banner was detected on the website.',
                'recommendation': 'Implement a GDPR-compliant cookie consent banner that appears before any tracking cookies are set.',
                'regulation': 'gdpr',
                'article': 'Article 7 - Conditions for consent',
                'frameworks': ['gdpr', 'lgpd']
            })
        elif not consent_banner['gdpr_compliant']:
            issues.append({
                'type': 'non_compliant_consent_banner',
                'severity': 'high',
                'title': 'Non-Compliant Consent Banner',
                'description': 'Consent banner found but lacks proper reject options or granular controls.',
                'recommendation': 'Update consent banner to include clear reject options and granular cookie category controls.',
                'regulation': 'gdpr',
                'article': 'Article 7 - Conditions for consent',
                'frameworks': ['gdpr', 'lgpd']
            })
        
        # Check for tracking without consent
        high_risk_cookies = [c for c in cookies if c.get('gdpr_risk') == 'high' and c.get('requires_consent')]
        if high_risk_cookies and not consent_banner.get('gdpr_compliant'):
            issues.append({
                'type': 'tracking_without_consent',
                'severity': 'critical',
                'title': 'Tracking Cookies Set Without Proper Consent',
                'description': f'Found {len(high_risk_cookies)} high-risk tracking cookies that require explicit consent.',
                'recommendation': 'Ensure all non-essential cookies are only set after explicit user consent.',
                'regulation': 'gdpr',
                'article': 'Article 6 - Lawfulness of processing',
                'frameworks': ['gdpr', 'lgpd']
            })
        
        # Privacy Policy Issues
        if not privacy_policy['found']:
            issues.append({
                'type': 'missing_privacy_policy',
                'severity': 'critical',
                'title': 'Privacy Policy Not Found',
                'description': 'No privacy policy link was detected on the website.',
                'recommendation': 'Add a comprehensive privacy policy that covers all data processing activities.',
                'regulation': 'gdpr',
                'article': 'Article 13 - Information to be provided',
                'frameworks': ['gdpr', 'ccpa', 'lgpd']
            })
        elif not privacy_policy['easily_accessible']:
            issues.append({
                'type': 'privacy_policy_not_accessible',
                'severity': 'medium',
                'title': 'Privacy Policy Not Easily Accessible',
                'description': 'Privacy policy link is not prominently displayed in the website footer.',
                'recommendation': 'Add a clearly visible privacy policy link in the footer.',
                'regulation': 'gdpr',
                'article': 'Article 12 - Transparent information',
                'frameworks': ['gdpr', 'ccpa', 'lgpd']
            })
        
        # CCPA Issues
        if not ccpa_compliance['do_not_sell_found']:
            issues.append({
                'type': 'missing_do_not_sell',
                'severity': 'high',
                'title': 'Missing "Do Not Sell" Link',
                'description': 'No "Do Not Sell My Personal Information" link found for CCPA compliance.',
                'recommendation': 'Add a "Do Not Sell My Personal Information" link for California users.',
                'regulation': 'ccpa',
                'article': 'Section 1798.135',
                'frameworks': ['ccpa']
            })
        
        # Google Analytics specific issues
        ga_scripts = [s for s in scripts if 'google-analytics' in s.get('src', '') or 'googletagmanager' in s.get('src', '')]
        if ga_scripts and not consent_banner.get('gdpr_compliant'):
            issues.append({
                'type': 'google_analytics_without_consent',
                'severity': 'high',
                'title': 'Google Analytics Loading Without Consent',
                'description': 'Google Analytics is loading before user consent is obtained.',
                'recommendation': 'Configure Google Analytics to load only after user consent for analytics cookies.',
                'regulation': 'gdpr',
                'article': 'Article 6 - Lawfulness of processing',
                'frameworks': ['gdpr', 'lgpd']
            })
        
        return issues

    def _calculate_framework_compliance(self, issues):
        """Calculate compliance scores for each framework"""
        framework_scores = {
            'gdpr': {'score': 100, 'issues': 0, 'status': 'compliant'},
            'ccpa': {'score': 100, 'issues': 0, 'status': 'compliant'},
            'lgpd': {'score': 100, 'issues': 0, 'status': 'compliant'}
        }
        
        # Deduct points based on issues
        for issue in issues:
            frameworks = issue.get('frameworks', [])
            severity = issue.get('severity', 'medium')
            
            # Point deductions based on severity
            deduction = {
                'critical': 30,
                'high': 20,
                'medium': 10,
                'low': 5
            }.get(severity, 10)
            
            for framework in frameworks:
                if framework in framework_scores:
                    framework_scores[framework]['score'] = max(0, framework_scores[framework]['score'] - deduction)
                    framework_scores[framework]['issues'] += 1
        
        # Determine status based on score
        for framework in framework_scores:
            score = framework_scores[framework]['score']
            if score >= 80:
                framework_scores[framework]['status'] = 'compliant'
            elif score >= 60:
                framework_scores[framework]['status'] = 'partially-compliant'
            else:
                framework_scores[framework]['status'] = 'non-compliant'
        
        return framework_scores

    def _calculate_overall_compliance_score(self, compliance_breakdown):
        """Calculate overall compliance score"""
        total_score = sum(framework['score'] for framework in compliance_breakdown.values())
        return round(total_score / len(compliance_breakdown))

    def _calculate_revenue_estimates(self, compliance_score, cookie_count, script_count):
        """Calculate realistic revenue estimates (clearly marked as projections)"""
        # Base calculation on compliance score and tracking complexity
        base_monthly = max(50, compliance_score * 2)
        
        # Adjust based on tracking complexity
        complexity_multiplier = 1 + (cookie_count * 0.1) + (script_count * 0.2)
        monthly_estimate = round(base_monthly * complexity_multiplier)
        
        return {
            'monthly': min(monthly_estimate, 1000),  # Cap at reasonable amount
            'annual': min(monthly_estimate * 12, 12000)
        }

    def _generate_recommendations(self, issues, compliance_breakdown):
        """Generate specific recommendations based on analysis"""
        recommendations = []
        
        # Framework-specific recommendations
        if compliance_breakdown['gdpr']['score'] < 80:
            recommendations.append('Implement GDPR-compliant cookie consent management')
        
        if compliance_breakdown['ccpa']['score'] < 80:
            recommendations.append('Add CCPA compliance features for California users')
        
        if compliance_breakdown['lgpd']['score'] < 80:
            recommendations.append('Ensure LGPD compliance for Brazilian users')
        
        # Issue-specific recommendations
        critical_issues = [i for i in issues if i.get('severity') == 'critical']
        if critical_issues:
            recommendations.append('Address critical compliance issues immediately')
        
        # Always include revenue opportunity
        recommendations.extend([
            'Start earning revenue from compliant consent management',
            'Reduce legal risk with proper cookie categorization',
            'Get professional compliance support and revenue sharing'
        ])
        
        return recommendations

    # Fallback methods for when BeautifulSoup is not available
    def _check_consent_banner_fallback(self, html_content):
        """Fallback consent banner detection without BeautifulSoup"""
        consent_indicators = ['cookie', 'consent', 'privacy', 'gdpr', 'accept']
        html_lower = html_content.lower()
        
        banner_found = any(indicator in html_lower for indicator in consent_indicators)
        has_reject = any(word in html_lower for word in ['reject', 'decline', 'deny'])
        
        return {
            'found': banner_found,
            'type': 'basic' if has_reject else 'simple',
            'has_reject_option': has_reject,
            'has_granular_controls': False,
            'gdpr_compliant': banner_found and has_reject
        }

    def _check_privacy_policy_fallback(self, html_content):
        """Fallback privacy policy detection without BeautifulSoup"""
        privacy_indicators = ['privacy policy', 'privacy notice', 'data protection']
        html_lower = html_content.lower()
        
        policy_found = any(indicator in html_lower for indicator in privacy_indicators)
        
        return {
            'found': policy_found,
            'url': None,
            'easily_accessible': policy_found,
            'gdpr_compliant': policy_found
        }

    def _check_ccpa_compliance_fallback(self, html_content):
        """Fallback CCPA compliance detection without BeautifulSoup"""
        ccpa_indicators = ['do not sell', 'ccpa', 'california privacy']
        html_lower = html_content.lower()
        
        do_not_sell_found = any(indicator in html_lower for indicator in ccpa_indicators)
        
        return {
            'do_not_sell_found': do_not_sell_found,
            'do_not_sell_url': None,
            'ccpa_compliant': do_not_sell_found
        }

    def _analyze_scripts_fallback(self, html_content, domain):
        """Fallback script analysis without BeautifulSoup"""
        scripts = []
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        
        for src in matches:
            script_info = self._categorize_script(src, domain)
            if script_info['tracking_service'] != 'unknown':
                scripts.append(script_info)
        
        return scripts

    def _categorize_script(self, src, domain):
        """Enhanced script categorization with compliance risk"""
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = f'https://{domain}{src}'
        
        script_info = {
            'type': 'external' if domain not in src else 'internal',
            'src': src,
            'tracking_service': 'unknown',
            'category': 'unknown',
            'gdpr_risk': 'low',
            'consent_gated': False
        }
        
        # Enhanced categorization
        for pattern, info in self.tracking_scripts.items():
            if pattern in src:
                script_info.update({
                    'tracking_service': info['service'],
                    'category': info['category'],
                    'gdpr_risk': info['gdpr_risk'],
                    'consent_gated': False  # Assume not gated unless detected otherwise
                })
                break
        
        return script_info

    def _analyze_scripts(self, soup, domain):
        """Enhanced script analysis with BeautifulSoup"""
        scripts = []
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags:
            src = script.get('src', '')
            if src:
                script_info = self._categorize_script(src, domain)
                if script_info['tracking_service'] != 'unknown':
                    scripts.append(script_info)
        
        return scripts

# Global variable to store active scans
active_scans = {}

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        company_name = data.get('company_name', '').strip()
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Check if user already exists
            cur.execute('SELECT id FROM users WHERE email = %s', (email,))
            if cur.fetchone():
                return jsonify({'error': 'Email already exists'}), 400
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Insert new user
            cur.execute('''
                INSERT INTO users (email, password_hash, company_name)
                VALUES (%s, %s, %s) RETURNING id
            ''', (email, password_hash, company_name))
            
            user_id = cur.fetchone()['id']
            conn.commit()
            
            # Create access token
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
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Registration error: {e}")
            return jsonify({'error': 'Registration failed'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
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
                return jsonify({'error': 'Invalid email or password'}), 401
            
            # Create access token - FIXED: Convert user ID to string
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
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Login failed'}), 500
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
        # Get user ID from JWT token - FIXED: Convert string back to int for database query
        user_id = int(get_jwt_identity())
        
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
            
        except Exception as e:
            logger.error(f"Profile fetch error: {e}")
            return jsonify({'error': 'Failed to fetch profile'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({'error': 'Profile fetch failed'}), 500

# Enhanced compliance scanning routes
@app.route('/api/compliance/real-scan', methods=['POST'])
@jwt_required()
def start_real_compliance_scan():
    """Start a real compliance scan with enhanced analysis"""
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL - Enhanced to handle URLs without protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        scan_id = f'real_{int(time.time())}_{user_id}'
        
        # Store scan in database
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute('''
                    INSERT INTO compliance_scans (scan_id, user_id, url, status, progress)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (scan_id, user_id, url, 'running', 0))
                conn.commit()
            except Exception as e:
                logger.error(f"Database error: {e}")
            finally:
                conn.close()
        
        # Start scan in background thread
        def run_scan():
            try:
                analyzer = EnhancedWebsiteAnalyzer()
                
                def progress_callback(progress, status):
                    active_scans[scan_id] = {
                        'status': 'running',
                        'progress': progress,
                        'current_step': status
                    }
                    
                    # Update database
                    conn = get_db_connection()
                    if conn:
                        try:
                            cur = conn.cursor()
                            cur.execute('''
                                UPDATE compliance_scans 
                                SET progress = %s 
                                WHERE scan_id = %s
                            ''', (progress, scan_id))
                            conn.commit()
                        except Exception as e:
                            logger.error(f"Progress update error: {e}")
                        finally:
                            conn.close()
                
                # Run the analysis
                results = analyzer.analyze_website(url, progress_callback)
                
                # Store results
                active_scans[scan_id] = {
                    'status': 'completed',
                    'progress': 100,
                    'results': results
                }
                
                # Update database with results
                conn = get_db_connection()
                if conn:
                    try:
                        cur = conn.cursor()
                        cur.execute('''
                            UPDATE compliance_scans 
                            SET status = %s, progress = %s, results = %s, completed_at = %s,
                                compliance_score = %s
                            WHERE scan_id = %s
                        ''', ('completed', 100, json.dumps(results), datetime.utcnow(), 
                              results.get('compliance_score', 0), scan_id))
                        conn.commit()
                    except Exception as e:
                        logger.error(f"Results storage error: {e}")
                    finally:
                        conn.close()
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Scan error: {error_msg}")
                
                active_scans[scan_id] = {
                    'status': 'failed',
                    'progress': 0,
                    'error': error_msg
                }
                
                # Update database with error
                conn = get_db_connection()
                if conn:
                    try:
                        cur = conn.cursor()
                        cur.execute('''
                            UPDATE compliance_scans 
                            SET status = %s, error_message = %s, completed_at = %s
                            WHERE scan_id = %s
                        ''', ('failed', error_msg, datetime.utcnow(), scan_id))
                        conn.commit()
                    except Exception as e:
                        logger.error(f"Error storage error: {e}")
                    finally:
                        conn.close()
        
        # Initialize scan status
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'current_step': 'Initializing scan...'
        }
        
        # Start background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Compliance scan started successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Scan start error: {e}")
        return jsonify({'error': 'Failed to start scan'}), 500

@app.route('/api/compliance/scan-status/<scan_id>', methods=['GET'])
@jwt_required()
def get_real_scan_status(scan_id):
    """Get the status of a real compliance scan"""
    try:
        user_id = int(get_jwt_identity())
        
        # Check active scans first
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            
            if scan_data['status'] == 'completed':
                # Remove from active scans after completion
                results = scan_data.get('results', {})
                del active_scans[scan_id]
                return jsonify(results), 200
            else:
                return jsonify({
                    'scan_id': scan_id,
                    'status': scan_data['status'],
                    'progress': scan_data['progress'],
                    'current_step': scan_data.get('current_step', ''),
                    'error': scan_data.get('error')
                }), 200
        
        # Check database for completed scans
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute('''
                SELECT status, progress, results, error_message 
                FROM compliance_scans 
                WHERE scan_id = %s AND user_id = %s
            ''', (scan_id, user_id))
            
            scan = cur.fetchone()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            if scan['status'] == 'completed' and scan['results']:
                return jsonify(scan['results']), 200
            else:
                return jsonify({
                    'scan_id': scan_id,
                    'status': scan['status'],
                    'progress': scan['progress'],
                    'error': scan['error_message']
                }), 200
                
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return jsonify({'error': 'Failed to check scan status'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Status check error: {e}")
        return jsonify({'error': 'Failed to check scan status'}), 500

# Dashboard routes
@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get website count
            cur.execute('SELECT COUNT(*) as count FROM websites WHERE user_id = %s', (user_id,))
            website_count = cur.fetchone()['count']
            
            # Get total scans
            cur.execute('SELECT COUNT(*) as count FROM compliance_scans WHERE user_id = %s', (user_id,))
            scan_count = cur.fetchone()['count']
            
            # Get average compliance score
            cur.execute('''
                SELECT AVG(compliance_score) as avg_score 
                FROM compliance_scans 
                WHERE user_id = %s AND status = 'completed'
            ''', (user_id,))
            avg_score_result = cur.fetchone()
            avg_score = round(avg_score_result['avg_score'] or 0)
            
            # Calculate estimated revenue (marked as projection)
            estimated_revenue = max(100, avg_score * website_count * 5)
            
            return jsonify({
                'websites': website_count,
                'total_scans': scan_count,
                'avg_compliance_score': avg_score,
                'estimated_monthly_revenue': estimated_revenue,
                'revenue_note': 'Revenue estimates are projections based on compliance scores and industry averages.'
            }), 200
            
        except Exception as e:
            logger.error(f"Dashboard stats error: {e}")
            return jsonify({'error': 'Failed to fetch dashboard stats'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to fetch dashboard stats'}), 500

@app.route('/api/dashboard/websites', methods=['GET'])
@jwt_required()
def get_dashboard_websites():
    """Get user's websites for dashboard"""
    try:
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            cur.execute('''
                SELECT w.*, cs.compliance_score, cs.completed_at as last_scan
                FROM websites w
                LEFT JOIN compliance_scans cs ON w.id = cs.website_id 
                    AND cs.status = 'completed'
                    AND cs.completed_at = (
                        SELECT MAX(completed_at) 
                        FROM compliance_scans 
                        WHERE website_id = w.id AND status = 'completed'
                    )
                WHERE w.user_id = %s
                ORDER BY w.created_at DESC
            ''', (user_id,))
            
            websites = cur.fetchall()
            
            return jsonify({
                'websites': [dict(website) for website in websites]
            }), 200
            
        except Exception as e:
            logger.error(f"Dashboard websites error: {e}")
            return jsonify({'error': 'Failed to fetch websites'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Dashboard websites error: {e}")
        return jsonify({'error': 'Failed to fetch websites'}), 500

@app.route('/api/dashboard/analytics', methods=['GET'])
@jwt_required()
def get_dashboard_analytics():
    """Get analytics data for dashboard"""
    try:
        user_id = int(get_jwt_identity())
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cur = conn.cursor()
            
            # Get scan history for the last 30 days
            cur.execute('''
                SELECT DATE(completed_at) as scan_date, COUNT(*) as scan_count,
                       AVG(compliance_score) as avg_score
                FROM compliance_scans 
                WHERE user_id = %s AND status = 'completed'
                    AND completed_at >= NOW() - INTERVAL '30 days'
                GROUP BY DATE(completed_at)
                ORDER BY scan_date DESC
            ''', (user_id,))
            
            scan_history = cur.fetchall()
            
            # Get compliance breakdown
            cur.execute('''
                SELECT compliance_score,
                       CASE 
                           WHEN compliance_score >= 80 THEN 'compliant'
                           WHEN compliance_score >= 60 THEN 'partially_compliant'
                           ELSE 'non_compliant'
                       END as status,
                       COUNT(*) as count
                FROM compliance_scans 
                WHERE user_id = %s AND status = 'completed'
                GROUP BY compliance_score, status
            ''', (user_id,))
            
            compliance_breakdown = cur.fetchall()
            
            return jsonify({
                'scan_history': [dict(row) for row in scan_history],
                'compliance_breakdown': [dict(row) for row in compliance_breakdown]
            }), 200
            
        except Exception as e:
            logger.error(f"Dashboard analytics error: {e}")
            return jsonify({'error': 'Failed to fetch analytics'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Dashboard analytics error: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500

# Health check endpoint
@app.route('/api/compliance/health', methods=['GET'])
def compliance_health_check():
    """Health check endpoint for compliance scanner"""
    return jsonify({
        'status': 'healthy',
        'service': 'enhanced-compliance-scanner',
        'timestamp': datetime.utcnow().isoformat(),
        'features': ['gdpr', 'ccpa', 'lgpd', 'real_scanning', 'revenue_estimates']
    }), 200

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)


