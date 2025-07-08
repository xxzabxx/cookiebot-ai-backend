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
        print(f"Database connection error: {e}")
        return None

# Initialize database tables
def init_db():
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database")
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
                name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'active',
                configuration JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Analytics events table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                event_data JSONB DEFAULT '{}',
                visitor_id VARCHAR(255),
                ip_address INET,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Revenue tracking table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS revenue_events (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                event_type VARCHAR(100) NOT NULL,
                amount DECIMAL(10,4) NOT NULL,
                currency VARCHAR(3) DEFAULT 'USD',
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance scans table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS compliance_scans (
                id SERIAL PRIMARY KEY,
                website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
                scan_type VARCHAR(100) NOT NULL,
                score INTEGER,
                results JSONB DEFAULT '{}',
                recommendations JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        cur.close()
        conn.close()
        print("Database tables created successfully!")
        return True
        
    except Exception as e:
        print(f"Database initialization error: {e}")
        conn.rollback()
        cur.close()
        conn.close()
        return False

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
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        # Check if user exists
        cur.execute('SELECT id FROM users WHERE email = %s', (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({'error': 'User already exists'}), 409
        
        # Create user
        cur.execute('''
            INSERT INTO users (email, password_hash, first_name, last_name, company)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        ''', (email, password_hash, first_name, last_name, company))
        
        user_id = cur.fetchone()['id']
        conn.commit()
        
        # Create access token
        access_token = create_access_token(identity=user_id)
        
        cur.close()
        conn.close()
        
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
        
        cur = conn.cursor()
        
        # Get user
        cur.execute('SELECT id, password_hash FROM users WHERE email = %s', (email,))
        user = cur.fetchone()
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            cur.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create access token
        access_token = create_access_token(identity=user['id'])
        
        cur.close()
        conn.close()
        
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
def get_profile():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        cur.execute('''
            SELECT id, email, first_name, last_name, company, subscription_tier, 
                   revenue_balance, created_at
            FROM users WHERE id = %s
        ''', (user_id,))
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(dict(user)), 200
        
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
        
        cur = conn.cursor()
        cur.execute('''
            SELECT id, domain, name, status, configuration, created_at, updated_at
            FROM websites WHERE user_id = %s ORDER BY created_at DESC
        ''', (user_id,))
        
        websites = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify([dict(website) for website in websites]), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/websites', methods=['POST'])
@jwt_required()
def create_website():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        domain = data.get('domain')
        name = data.get('name', domain)
        configuration = data.get('configuration', {})
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        # Check if domain already exists for this user
        cur.execute('SELECT id FROM websites WHERE user_id = %s AND domain = %s', (user_id, domain))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({'error': 'Website already exists'}), 409
        
        # Create website
        cur.execute('''
            INSERT INTO websites (user_id, domain, name, configuration)
            VALUES (%s, %s, %s, %s) RETURNING id
        ''', (user_id, domain, name, json.dumps(configuration)))
        
        website_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            'message': 'Website created successfully',
            'website_id': website_id
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Analytics routes
@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_analytics():
    try:
        user_id = get_jwt_identity()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        # Get website count
        cur.execute('SELECT COUNT(*) as count FROM websites WHERE user_id = %s', (user_id,))
        website_count = cur.fetchone()['count']
        
        # Get total events today
        cur.execute('''
            SELECT COUNT(*) as count FROM analytics_events ae
            JOIN websites w ON ae.website_id = w.id
            WHERE w.user_id = %s AND DATE(ae.created_at) = CURRENT_DATE
        ''', (user_id,))
        events_today = cur.fetchone()['count']
        
        # Get revenue balance
        cur.execute('SELECT revenue_balance FROM users WHERE id = %s', (user_id,))
        revenue_balance = float(cur.fetchone()['revenue_balance'] or 0)
        
        # Get recent events
        cur.execute('''
            SELECT ae.event_type, ae.created_at, w.domain
            FROM analytics_events ae
            JOIN websites w ON ae.website_id = w.id
            WHERE w.user_id = %s
            ORDER BY ae.created_at DESC
            LIMIT 10
        ''', (user_id,))
        recent_events = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'website_count': website_count,
            'events_today': events_today,
            'revenue_balance': revenue_balance,
            'recent_events': [dict(event) for event in recent_events]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Public tracking endpoints (no authentication required)
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
        
        cur = conn.cursor()
        
        # Verify website exists
        cur.execute('SELECT id FROM websites WHERE id = %s', (website_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({'error': 'Website not found'}), 404
        
        # Track event
        cur.execute('''
            INSERT INTO analytics_events (website_id, event_type, event_data, visitor_id, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (
            website_id,
            event_type,
            json.dumps(event_data),
            visitor_id,
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'message': 'Event tracked successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected' if get_db_connection() else 'disconnected'
    }), 200

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

