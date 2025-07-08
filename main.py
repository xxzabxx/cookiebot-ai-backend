from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
import bcrypt
from datetime import datetime, timedelta
import uuid
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urlparse

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
], supports_credentials=True)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """Get database connection"""
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def init_database():
    """Initialize database tables"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
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
        """)
        
        # Create websites table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS websites (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                domain VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'active',
                configuration JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create analytics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                event_data JSONB DEFAULT '{}',
                visitor_id VARCHAR(255),
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create revenue table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS revenue (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                amount DECIMAL(10,2) NOT NULL,
                revenue_type VARCHAR(100) NOT NULL,
                transaction_data JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        return False

# Initialize database on startup
init_database()

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
            
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        cursor.execute("""
            INSERT INTO users (email, password_hash, first_name, last_name, company)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (email, password_hash, first_name, last_name, company))
        
        user_id = cursor.fetchone()['id']
        conn.commit()
        cursor.close()
        conn.close()
        
        # Create access token
        access_token = create_access_token(identity=user_id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'user_id': user_id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
            
        cursor = conn.cursor()
        
        # Get user
        cursor.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        cursor.close()
        conn.close()
        
        # Create access token
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user_id': user['id']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User profile routes
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, email, first_name, last_name, company, subscription_tier, 
                   revenue_balance, created_at
            FROM users WHERE id = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(dict(user)), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Update user profile
        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, company = %s, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (data.get('first_name'), data.get('last_name'), data.get('company'), user_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Website management routes
@app.route('/api/websites', methods=['GET'])
@jwt_required()
def get_websites():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, domain, name, status, configuration, created_at
            FROM websites WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))
        
        websites = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify([dict(website) for website in websites]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites', methods=['POST'])
@jwt_required()
def add_website():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        domain = data.get('domain')
        name = data.get('name', domain)
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Check if website already exists for this user
        cursor.execute("SELECT id FROM websites WHERE user_id = %s AND domain = %s", (user_id, domain))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Website already exists'}), 409
        
        # Add website
        cursor.execute("""
            INSERT INTO websites (user_id, domain, name, status)
            VALUES (%s, %s, %s, 'active')
            RETURNING id, domain, name, status, created_at
        """, (user_id, domain, name))
        
        website = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify(dict(website)), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites/<int:website_id>', methods=['DELETE'])
@jwt_required()
def delete_website(website_id):
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Delete website (only if owned by user)
        cursor.execute("DELETE FROM websites WHERE id = %s AND user_id = %s", (website_id, user_id))
        
        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Website not found'}), 404
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Website deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Analytics routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_analytics_dashboard():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Get website count
        cursor.execute("SELECT COUNT(*) as website_count FROM websites WHERE user_id = %s", (user_id,))
        website_count = cursor.fetchone()['website_count']
        
        # Get today's events
        cursor.execute("""
            SELECT COUNT(*) as events_today 
            FROM analytics a
            JOIN websites w ON a.website_id = w.id
            WHERE w.user_id = %s AND DATE(a.created_at) = CURRENT_DATE
        """, (user_id,))
        events_today = cursor.fetchone()['events_today']
        
        # Get revenue balance
        cursor.execute("SELECT revenue_balance FROM users WHERE id = %s", (user_id,))
        revenue_balance = float(cursor.fetchone()['revenue_balance'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'website_count': website_count,
            'events_today': events_today,
            'revenue_balance': revenue_balance,
            'consent_rate': 78.5,  # Mock data for now
            'total_visitors': events_today * 10  # Mock calculation
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Public tracking endpoint (no auth required)
@app.route('/api/public/track', methods=['POST'])
def track_event():
    try:
        data = request.get_json()
        website_id = data.get('website_id')
        event_type = data.get('event_type')
        event_data = data.get('event_data', {})
        visitor_id = data.get('visitor_id')
        
        if not website_id or not event_type:
            return jsonify({'error': 'website_id and event_type are required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cursor = conn.cursor()
        
        # Track event
        cursor.execute("""
            INSERT INTO analytics (website_id, event_type, event_data, visitor_id, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            website_id, 
            event_type, 
            json.dumps(event_data),
            visitor_id,
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Event tracked successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Test database connection
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            conn.close()
            db_status = "connected"
        else:
            db_status = "disconnected"
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': db_status,
            'version': '2.0.0'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'error',
            'error': str(e)
        }), 500

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API',
        'version': '2.0.0',
        'status': 'running',
        'features': [
            'User Authentication',
            'Website Management', 
            'Analytics Tracking',
            'Revenue Tracking',
            'Supabase Integration'
        ]
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)


