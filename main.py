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
                }
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
            'tracking': '/api/public/track'
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
        if not url.startswith(('http://', 'https://' )):
            url = 'https://' + url
        
        from urllib.parse import urlparse
        domain = urlparse(url ).netloc
        
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
                    'recommendation': 'Implement a GDPR-compliant cookie consent banner that appears before any tracking cookies are set.',
                    'regulation': 'gdpr',
                    'article': 'Article 7'
                },
                {
                    'type': 'tracking_without_consent',
                    'severity': 'critical',
                    'title': 'Tracking Cookies Set Without Consent',
                    'description': 'Google Analytics and other tracking scripts are loading without user consent.',
                    'recommendation': 'Ensure all non-essential cookies are only set after explicit user consent.',
                    'regulation': 'gdpr',
                    'article': 'Article 7'
                },
                {
                    'type': 'missing_privacy_policy',
                    'severity': 'high',
                    'title': 'Privacy Policy Not Easily Accessible',
                    'description': 'Privacy policy link is not prominently displayed in the website footer.',
                    'recommendation': 'Add a clearly visible privacy policy link in the footer and ensure it covers all data processing activities.',
                    'regulation': 'gdpr',
                    'article': 'Article 13'
                },
                {
                    'type': 'google_analytics_without_consent',
                    'severity': 'high',
                    'title': 'Google Analytics Loading Without Consent',
                    'description': 'Google Analytics is loading before user consent is obtained.',
                    'recommendation': 'Configure Google Analytics to load only after user consent for analytics cookies.',
                    'regulation': 'gdpr',
                    'article': 'Article 6'
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
        
        return jsonify(demo_results ), 200
        
    except Exception as e:
        logger.error(f"Error in demo scan: {e}")
        return jsonify({'error': 'Demo scan failed'}), 500

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

