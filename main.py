from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
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
CORS(app, origins=[
    "https://cookiebot.ai",
    "https://cookiebot-ai-website.netlify.app",
    "http://localhost:3000",
    "http://localhost:5173"
], supports_credentials=True )

# In-memory storage for testing (will be replaced with database later)
users_db = {}
websites_db = {}
analytics_db = []

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
        
        # Check if user exists
        if email in users_db:
            return jsonify({'error': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        user_id = len(users_db) + 1
        users_db[email] = {
            'id': user_id,
            'email': email,
            'password_hash': password_hash,
            'first_name': first_name,
            'last_name': last_name,
            'company': company,
            'subscription_tier': 'free',
            'revenue_balance': 0.00,
            'created_at': datetime.utcnow().isoformat()
        }
        
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
        
        # Get user
        user = users_db.get(email)
        
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create access token
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user_id': user['id']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'in-memory (testing mode)'
    }), 200

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API',
        'version': '1.0.0',
        'status': 'running'
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
