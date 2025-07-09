from flask import Flask, jsonify
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        DATABASE_URL = os.environ.get('DATABASE_URL')
        
        if not DATABASE_URL:
            return jsonify({
                'status': 'unhealthy',
                'error': 'DATABASE_URL not found'
            }), 500
        
        # Test psycopg2 import
        try:
            import psycopg2
            logger.info("psycopg2 imported successfully")
        except ImportError as e:
            return jsonify({
                'status': 'unhealthy',
                'error': f'psycopg2 import failed: {str(e)}'
            }), 500
        
        # Test database connection with detailed error
        try:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            cur.execute("SELECT version()")
            version = cur.fetchone()[0]
            cur.close()
            conn.close()
            
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'database_version': version[:100]  # Truncate for display
            }), 200
            
        except Exception as e:
            # Return detailed error information
            return jsonify({
                'status': 'unhealthy',
                'database': 'disconnected',
                'error_type': type(e).__name__,
                'error_message': str(e)[:500],  # First 500 chars of error
                'database_url_format': DATABASE_URL[:50] + '...' if len(DATABASE_URL) > 50 else DATABASE_URL
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': f'Health check failed: {str(e)}'
        }), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API - Diagnostic Mode',
        'version': '2.0.0-debug'
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
