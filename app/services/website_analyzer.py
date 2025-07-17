"""
Real Website Analyzer Service for CookieBot.ai application.
"""

import requests
from bs4 import BeautifulSoup
import re
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any, Optional
import time
import uuid

from ..models.compliance import TrackingService, CookieCategory

logger = logging.getLogger(__name__)


class RealWebsiteAnalyzer:
    """Real website analyzer for compliance scanning"""
    
    def __init__(self):
        self.tracking_services = TrackingService.SERVICES
        self.cookie_patterns = self._get_cookie_patterns()
    
    def _get_cookie_patterns(self) -> Dict[str, Dict[str, str]]:
        """Get common cookie patterns for detection"""
        return {
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
    
    def analyze_website(self, url: str, scan_id: str) -> Dict[str, Any]:
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
    
    def _fetch_website(self, url: str, scan_id: str) -> Optional[requests.Response]:
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
    
    def _analyze_content(self, html_content: str, url: str, domain: str, scan_id: str) -> Dict[str, Any]:
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
        
        # Check for consent banner
        logger.info(f"[SCAN {scan_id}] Checking for consent banner...")
        consent_banner = self._check_consent_banner(html_content, soup, scan_id)
        
        # Calculate compliance score
        logger.info(f"[SCAN {scan_id}] Calculating compliance score...")
        compliance_score = self._calculate_compliance_score(scripts, cookies, consent_banner, html_content, scan_id)
        
        # Calculate revenue potential
        logger.info(f"[SCAN {scan_id}] Calculating revenue potential...")
        revenue_data = self._calculate_revenue_potential(scripts, cookies, scan_id)
        
        # Create compliance breakdown
        compliance_breakdown = self._create_compliance_breakdown(scripts, cookies, consent_banner, compliance_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(scripts, cookies, consent_banner, compliance_score)
        
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
            'consent_banner': consent_banner,
            'potential_earnings': revenue_data['monthly'],
            'annual_earnings': revenue_data['annual'],
            'recommendations': recommendations,
            'scan_duration': 0  # Would be calculated in real implementation
        }
        
        logger.info(f"[SCAN {scan_id}] Final result: domain={domain}, score={compliance_score}, cookies={len(cookies)}, scripts={len(scripts)}")
        
        return result
    
    def _analyze_scripts(self, html_content: str, soup: Optional[BeautifulSoup], scan_id: str) -> List[Dict[str, Any]]:
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
                                    'consent_gated': self._check_consent_gating(content),
                                    'privacy_policy': service_info.get('privacy_policy')
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
                                'consent_gated': False,
                                'privacy_policy': service_info.get('privacy_policy')
                            })
                            break
            
            logger.info(f"[SCAN {scan_id}] Detected {len(scripts)} tracking scripts")
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Script analysis error: {str(e)}")
        
        return scripts
    
    def _analyze_cookies(self, html_content: str, soup: Optional[BeautifulSoup], scan_id: str) -> List[Dict[str, Any]]:
        """Analyze potential cookies"""
        cookies = []
        
        try:
            # Look for cookie references in the HTML
            for cookie_name, cookie_info in self.cookie_patterns.items():
                if cookie_name in html_content:
                    cookies.append({
                        'name': cookie_name,
                        'category': cookie_info['category'],
                        'purpose': cookie_info['purpose'],
                        'domain': '',  # Would need actual cookie inspection
                        'secure': False,  # Default assumption
                        'http_only': cookie_info['category'] == 'necessary',
                        'expiry': 'session'  # Default assumption
                    })
            
            logger.info(f"[SCAN {scan_id}] Detected {len(cookies)} potential cookies")
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Cookie analysis error: {str(e)}")
        
        return cookies
    
    def _check_consent_banner(self, html_content: str, soup: Optional[BeautifulSoup], scan_id: str) -> Dict[str, Any]:
        """Check for consent banner presence and features"""
        try:
            consent_indicators = ['cookie', 'consent', 'privacy', 'gdpr', 'accept', 'decline', 'preferences']
            banner_found = any(indicator in html_content.lower() for indicator in consent_indicators)
            
            # Check for specific consent management platforms
            consent_platforms = {
                'cookiebot': r'cookiebot',
                'onetrust': r'onetrust',
                'cookiepro': r'cookiepro',
                'trustarc': r'trustarc',
                'quantcast': r'quantcast',
                'iubenda': r'iubenda'
            }
            
            detected_platform = None
            for platform, pattern in consent_platforms.items():
                if re.search(pattern, html_content, re.IGNORECASE):
                    detected_platform = platform
                    break
            
            # Check for granular controls
            granular_controls = bool(re.search(r'(functional|statistics|marketing|analytics|advertising)', html_content, re.IGNORECASE))
            
            return {
                'present': banner_found,
                'platform': detected_platform,
                'granular_controls': granular_controls,
                'decline_option': 'decline' in html_content.lower() or 'reject' in html_content.lower()
            }
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Consent banner check error: {str(e)}")
            return {'present': False, 'platform': None, 'granular_controls': False, 'decline_option': False}
    
    def _check_consent_gating(self, script_content: str) -> bool:
        """Check if script is properly consent-gated"""
        consent_patterns = [
            r'consent.*granted',
            r'cookie.*accepted',
            r'gdpr.*consent',
            r'analytics.*consent'
        ]
        
        return any(re.search(pattern, script_content, re.IGNORECASE) for pattern in consent_patterns)
    
    def _calculate_compliance_score(self, scripts: List[Dict], cookies: List[Dict], 
                                  consent_banner: Dict, html_content: str, scan_id: str) -> int:
        """Calculate overall compliance score"""
        try:
            score = 100
            
            # Deduct points for tracking without consent
            ungated_tracking = [s for s in scripts if s.get('tracking_service') and not s.get('consent_gated', False)]
            score -= len(ungated_tracking) * 15
            
            # Deduct points for marketing cookies
            marketing_cookies = [c for c in cookies if c.get('category') == 'marketing']
            score -= len(marketing_cookies) * 10
            
            # Deduct points for no consent banner
            if not consent_banner.get('present'):
                score -= 25
            
            # Bonus points for good practices
            if consent_banner.get('granular_controls'):
                score += 10
            
            if consent_banner.get('decline_option'):
                score += 5
            
            # Ensure score is between 0 and 100
            score = max(0, min(100, score))
            
            logger.info(f"[SCAN {scan_id}] Calculated compliance score: {score}")
            
            return score
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Score calculation error: {str(e)}")
            return 0
    
    def _calculate_revenue_potential(self, scripts: List[Dict], cookies: List[Dict], scan_id: str) -> Dict[str, float]:
        """Calculate revenue potential"""
        try:
            # Base revenue calculation
            base_monthly = 100.0
            
            # Add revenue based on tracking services (more tracking = more revenue potential)
            tracking_count = len([s for s in scripts if s.get('tracking_service')])
            revenue_per_service = 50.0
            
            monthly = base_monthly + (tracking_count * revenue_per_service)
            annual = monthly * 12
            
            logger.info(f"[SCAN {scan_id}] Calculated revenue: monthly=${monthly}, annual=${annual}")
            
            return {
                'monthly': monthly,
                'annual': annual
            }
            
        except Exception as e:
            logger.error(f"[SCAN {scan_id}] Revenue calculation error: {str(e)}")
            return {'monthly': 100.0, 'annual': 1200.0}
    
    def _create_compliance_breakdown(self, scripts: List[Dict], cookies: List[Dict], 
                                   consent_banner: Dict, compliance_score: int) -> Dict[str, Dict]:
        """Create compliance breakdown by regulation"""
        return {
            'gdpr': {
                'score': max(0, compliance_score - 10),
                'issues': len([s for s in scripts if not s.get('consent_gated', False)]),
                'status': 'non-compliant' if compliance_score < 70 else 'compliant',
                'requirements': [
                    'Explicit consent for non-essential cookies',
                    'Granular consent options',
                    'Easy withdrawal of consent',
                    'Clear privacy information'
                ]
            },
            'ccpa': {
                'score': max(0, compliance_score - 5),
                'issues': len([c for c in cookies if c.get('category') == 'marketing']),
                'status': 'partially-compliant' if compliance_score < 80 else 'compliant',
                'requirements': [
                    'Do Not Sell My Personal Information link',
                    'Clear privacy policy',
                    'Data deletion rights',
                    'Opt-out mechanisms'
                ]
            },
            'lgpd': {
                'score': compliance_score,
                'issues': len([s for s in scripts if s.get('tracking_service')]),
                'status': 'non-compliant' if compliance_score < 75 else 'compliant',
                'requirements': [
                    'Lawful basis for processing',
                    'Data subject rights',
                    'Privacy by design',
                    'Data protection officer'
                ]
            }
        }
    
    def _generate_recommendations(self, scripts: List[Dict], cookies: List[Dict], 
                                consent_banner: Dict, compliance_score: int) -> List[str]:
        """Generate specific recommendations based on analysis"""
        recommendations = []
        
        if not consent_banner.get('present'):
            recommendations.append('Implement a cookie consent banner to comply with GDPR and other privacy laws')
        
        if not consent_banner.get('granular_controls'):
            recommendations.append('Add granular consent controls for different cookie categories')
        
        if not consent_banner.get('decline_option'):
            recommendations.append('Provide a clear option to decline non-essential cookies')
        
        ungated_scripts = [s for s in scripts if s.get('tracking_service') and not s.get('consent_gated', False)]
        if ungated_scripts:
            recommendations.append(f'Gate {len(ungated_scripts)} tracking scripts behind user consent')
        
        marketing_cookies = [c for c in cookies if c.get('category') == 'marketing']
        if marketing_cookies:
            recommendations.append(f'Ensure {len(marketing_cookies)} marketing cookies require explicit consent')
        
        if compliance_score < 70:
            recommendations.append('Consider implementing CookieBot.ai for automated compliance management')
        
        recommendations.append('Start earning revenue from your consent banner with Privacy Insights')
        recommendations.append('Get 60% revenue share from affiliate partnerships')
        
        return recommendations
    
    def _create_error_result(self, url: str, domain: str, error_message: str) -> Dict[str, Any]:
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
            'consent_banner': {'present': False},
            'potential_earnings': 0,
            'annual_earnings': 0,
            'recommendations': [
                'Please check the URL and try again',
                'Ensure the website is accessible',
                'Contact support if the issue persists'
            ]
        }

