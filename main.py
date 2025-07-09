from flask import Flask, jsonify
import os
import sys
import traceback

app = Flask(__name__)

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        DATABASE_URL = os.environ.get('DATABASE_URL')
        
        # Test psycopg2 import
        try:
            import psycopg2
            from psycopg2 import OperationalError, DatabaseError
        except ImportError as e:
            return jsonify({
                'status': 'unhealthy',
                'error': f'psycopg2 import failed: {str(e)}'
            }), 500
        
        # Test connection with maximum error detail
        error_details = []
        
        try:
            # Test 1: Basic connection
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            cur.execute("SELECT 1")
            result = cur.fetchone()
            cur.close()
            conn.close()
            
            return jsonify({
                'status': 'healthy',
                'database': 'connected',
                'test_query_result': result[0]
            }), 200
            
        except Exception as e:
            # Capture every possible detail about the error
            error_info = {
                'error_type': str(type(e).__name__),
                'error_str': str(e),
                'error_repr': repr(e),
                'error_args': str(e.args) if hasattr(e, 'args') else 'No args',
                'traceback': traceback.format_exc()
            }
            
            # Try to get more specific psycopg2 error details
            if hasattr(e, 'pgcode'):
                error_info['pgcode'] = e.pgcode
            if hasattr(e, 'pgerror'):
                error_info['pgerror'] = str(e.pgerror)
            if hasattr(e, 'diag'):
                error_info['diag'] = str(e.diag)
                
            error_details.append(error_info)
        
        # Test 2: Try with different SSL modes
        ssl_modes = ['require', 'prefer', 'disable']
        for ssl_mode in ssl_modes:
            try:
                test_url = DATABASE_URL.split('?')[0] + f'?sslmode={ssl_mode}'
                conn = psycopg2.connect(test_url)
                conn.close()
                
                return jsonify({
                    'status': 'healthy',
                    'database': 'connected',
                    'ssl_mode_that_worked': ssl_mode
                }), 200
                
            except Exception as e:
                error_details.append({
                    'ssl_mode': ssl_mode,
                    'error_type': str(type(e).__name__),
                    'error_message': str(e),
                    'error_args': str(e.args) if hasattr(e, 'args') else 'No args'
                })
        
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'database_url_length': len(DATABASE_URL),
            'database_url_start': DATABASE_URL[:60],
            'error_details': error_details
        }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': f'Diagnostic failed: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        'message': 'CookieBot.ai Backend API - Maximum Error Detail',
        'version': '2.0.0-max-diagnostic'
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
