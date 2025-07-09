from flask import Flask, jsonify
import os
import logging

logging.basicConfig(level=logging.INFO )
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        DATABASE_URL = os.environ.get('DATABASE_URL')
        
        # Test psycopg2 import
        try:
            import psycopg2
            from psycopg2 import OperationalError
        except ImportError as e:
            return jsonify({
                'status': 'unhealthy',
                'error': f'psycopg2 import failed: {str(e)}'
            }), 500
        
        # Parse DATABASE_URL to show components
        try:
            from urllib.parse import urlparse
            parsed = urlparse(DATABASE_URL)
            
            connection_info = {
                'host': parsed.hostname,
                'port': parsed.port,
                'database': parsed.path[1:] if parsed.path else None,
                'username': parsed.username,
                'password_length': len(parsed.password) if parsed.password else 0
            }
        except Exception as e:
            connection_info = {'parse_error': str(e)}
        
        # Test different connection approaches
        test_results = []
        
        # Test 1: Basic connection
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.close()
            test_results.append({'test': 'basic_connection', 'result': 'SUCCESS'})
        except OperationalError as e:
            test_results.append({
                'test': 'basic_connection', 
                'result': 'FAILED',
                'error': str(e)[:200]
            })
        except Exception as e:
            test_results.append({
                'test': 'basic_connection', 
                'result': 'FAILED',
                'error': f'{type(e).__name__}: {str(e)[:200]}'
            })
        
        # Test 2: Connection with explicit SSL
        try:
            ssl_url = DATABASE_URL
            if '?sslmode=' not in ssl_url:
                ssl_url += '?sslmode=require'
            
            conn = psycopg2.connect(ssl_url)
            conn.close()
            test_results.append({'test': 'ssl_connection', 'result': 'SUCCESS'})
        except Exception as e:
            test_results.append({
                'test': 'ssl_connection', 
                'result': 'FAILED',
                'error': f'{type(e).__name__}: {str(e)[:200]}'
            })
        
        return jsonify({
            'status': 'diagnostic',
            'connection_info': connection_info,
            'test_results': test_results,
            'database_url_length': len(DATABASE_URL)
        }), 200
            
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': f'Diagnostic failed: {str(e)}'
        }), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API - Full Diagnostic',
        'version': '2.0.0-diagnostic'
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
