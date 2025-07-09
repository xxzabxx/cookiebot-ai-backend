from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
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
CORS(app, origins=[
    "https://cookiebot.ai",
    "https://cookiebot-ai-website.netlify.app",
    "http://localhost:3000",
    "http://localhost:5173"
], supports_credentials=True )

# Database configuration with detailed error handling
DATABASE_URL = os.environ.get('DATABASE_URL')
logger.info(f"DATABASE_URL present: {bool(DATABASE_URL)}")

if not DATABASE_URL:
    logger.error("DATABASE_URL environment variable is missing")
    raise ValueError("DATABASE_URL environment variable is required")

# Try to import and test PostgreSQL connection
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    logger.info("psycopg2 imported successfully")
    
    # Test database connection
    def test_db_connection():
        try:
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
            cur = conn.cursor()
            cur.execute("SELECT 1 as test")
            result = cur.fetchone()
            cur.close()
            conn.close()
            logger.info(f"Database connection test successful: {result}")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    # Test connection on startup
    db_connected = test_db_connection()
    logger.info(f"Database connected: {db_connected}")
    
except ImportError as e:
    logger.error(f"Failed to import psycopg2: {e}")
    raise
except Exception as e:
    logger.error(f"Database setup error: {e}")
    raise

def get_db_connection():
    """Get a database connection"""
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        logger.error(f"Error getting database connection: {e}")
        raise

def create_tables():
    """Create database tables if they don't exist"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                subscription_plan VARCHAR(50) DEFAULT 'free',
                revenue_balance DECIMAL(10,2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Websites table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS websites (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                domain VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                visitors_today INTEGER DEFAULT 0,
                consent_rate DECIMAL(5,2) DEFAULT 0.00,
                revenue_today DECIMAL(10,2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Analytics table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                website_id UUID REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(50) NOT NULL,
                event_data JSONB,
                revenue_amount DECIMAL(10,2) DEFAULT 0.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        logger.info("Database tables created successfully")
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error creating tables: {e}")
        raise
    finally:
        if conn:
            conn.close()

# Initialize database on startup
try:
    create_tables()
    logger.info("Database initialization completed")
except Exception as e:
    logger.error(f"Failed to initialize database: {e}")
    # Don't raise here - let the app start and show the error in health check

# Helper functions
def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def get_user_by_email(email):
    """Get user by email from database"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        return cur.fetchone()
    except Exception as e:
        logger.error(f"Error getting user by email: {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_user_by_id(user_id):
    """Get user by ID from database"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cur.fetchone()
    except Exception as e:
        logger.error(f"Error getting user by ID: {e}")
        return None
    finally:
        if conn:
            conn.close()

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logger.info(f"Registration attempt for email: {data.get('email', 'unknown')}")
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        first_name = data['first_name'].strip()
        last_name = data['last_name'].strip()
        
        # Check if user already exists
        if get_user_by_email(email):
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create user in database
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute("""
                INSERT INTO users (email, password_hash, first_name, last_name)
                VALUES (%s, %s, %s, %s)
                RETURNING id, email, first_name, last_name, subscription_plan, revenue_balance, created_at
            """, (email, password_hash, first_name, last_name))
            
            user = cur.fetchone()
            conn.commit()
            
            # Create access token
            access_token = create_access_token(identity=str(user['id']))
            
            logger.info(f"User registered successfully: {email}")
            
            return jsonify({
                'message': 'User registered successfully',
                'access_token': access_token,
                'user': {
                    'id': str(user['id']),
                    'email': user['email'],
                    'first_name': user['first_name'],
                    'last_name': user['last_name'],
                    'subscription_plan': user['subscription_plan'],
                    'revenue_balance': float(user['revenue_balance'])
                }
            }), 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error during registration: {e}")
            return jsonify({'error': f'Database error during registration: {str(e)}'}), 500
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Get user from database
        user = get_user_by_email(email)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create access token
        access_token = create_access_token(identity=str(user['id']))
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'subscription_plan': user['subscription_plan'],
                'revenue_balance': float(user['revenue_balance'])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

# User routes
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        user_id = get_jwt_identity()
        user = get_user_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'subscription_plan': user['subscription_plan'],
                'revenue_balance': float(user['revenue_balance'])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Profile error: {e}")
        return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500

# Website management routes
@app.route('/api/websites', methods=['GET'])
@jwt_required()
def get_websites():
    try:
        user_id = get_jwt_identity()
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute("""
                SELECT id, domain, status, visitors_today, consent_rate, revenue_today, created_at
                FROM websites 
                WHERE user_id = %s 
                ORDER BY created_at DESC
            """, (user_id,))
            
            websites = cur.fetchall()
            
            return jsonify({
                'websites': [
                    {
                        'id': str(website['id']),
                        'domain': website['domain'],
                        'status': website['status'],
                        'visitors_today': website['visitors_today'],
                        'consent_rate': float(website['consent_rate']),
                        'revenue_today': float(website['revenue_today'])
                    }
                    for website in websites
                ]
            }), 200
            
        except Exception as e:
            logger.error(f"Database error getting websites: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        logger.error(f"Get websites error: {e}")
        return jsonify({'error': f'Failed to get websites: {str(e)}'}), 500

@app.route('/api/websites', methods=['POST'])
@jwt_required()
def add_website():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data.get('domain'):
            return jsonify({'error': 'Domain is required'}), 400
        
        domain = data['domain'].strip().lower()
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Check if domain already exists for this user
            cur.execute("""
                SELECT id FROM websites WHERE user_id = %s AND domain = %s
            """, (user_id, domain))
            
            if cur.fetchone():
                return jsonify({'error': 'Domain already exists'}), 409
            
            # Add new website
            cur.execute("""
                INSERT INTO websites (user_id, domain)
                VALUES (%s, %s)
                RETURNING id, domain, status, visitors_today, consent_rate, revenue_today, created_at
            """, (user_id, domain))
            
            website = cur.fetchone()
            conn.commit()
            
            return jsonify({
                'message': 'Website added successfully',
                'website': {
                    'id': str(website['id']),
                    'domain': website['domain'],
                    'status': website['status'],
                    'visitors_today': website['visitors_today'],
                    'consent_rate': float(website['consent_rate']),
                    'revenue_today': float(website['revenue_today'])
                }
            }), 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error adding website: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        logger.error(f"Add website error: {e}")
        return jsonify({'error': f'Failed to add website: {str(e)}'}), 500

# Analytics routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_analytics():
    try:
        user_id = get_jwt_identity()
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Get user's total revenue
            cur.execute("""
                SELECT COALESCE(SUM(revenue_balance), 0) as total_revenue
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
            logger.error(f"Database error getting analytics: {e}")
            return jsonify({'error': f'Database error: {str(e)}'}), 500
        finally:
            if conn:
                conn.close()
        
    except Exception as e:
        logger.error(f"Analytics error: {e}")
        return jsonify({'error': f'Failed to get analytics: {str(e)}'}), 500

# Public tracking route (no auth required)
@app.route('/api/public/track', methods=['POST'])
def track_event():
    try:
        data = request.get_json()
        
        # For now, just log the event
        logger.info(f"Tracking event: {data}")
        
        return jsonify({
            'message': 'Event tracked successfully',
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Tracking error: {e}")
        return jsonify({'error': f'Failed to track event: {str(e)}'}), 500

# Health check endpoint with detailed database status
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test database connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1 as test, version() as db_version")
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'database_version': result['db_version'] if result else 'unknown',
            'environment_vars': {
                'DATABASE_URL': bool(os.environ.get('DATABASE_URL')),
                'JWT_SECRET_KEY': bool(os.environ.get('JWT_SECRET_KEY')),
                'SUPABASE_URL': bool(os.environ.get('SUPABASE_URL'))
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'disconnected',
            'error': str(e),
            'environment_vars': {
                'DATABASE_URL': bool(os.environ.get('DATABASE_URL')),
                'JWT_SECRET_KEY': bool(os.environ.get('JWT_SECRET_KEY')),
                'SUPABASE_URL': bool(os.environ.get('SUPABASE_URL'))
            }
        }), 500

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API',
        'version': '2.0.0',
        'status': 'running',
        'database': 'supabase'
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

