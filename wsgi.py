#!/usr/bin/env python3
"""
Comprehensive debugging WSGI entry point
This file adds extensive diagnostics to understand why real requests fail
"""

import os
import sys
import traceback
from datetime import datetime

print("🚀 WSGI: Starting CookieBot AI Backend...")
print(f"🚀 WSGI: Python version: {sys.version}")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app with detailed error handling
app = None
try:
    print("🔍 WSGI: Attempting to import Flask app from main.py...")
    from main import app as flask_app
    
    if flask_app is None:
        raise ValueError("Flask app is None - check main.py app creation")
    
    print(f"✅ WSGI: Flask app imported successfully!")
    print(f"🔍 WSGI: App type: {type(flask_app)}")
    print(f"🔍 WSGI: App name: {getattr(flask_app, 'name', 'unknown')}")
    
    # Inspect Flask app configuration
    print("🔍 WSGI: Inspecting Flask app configuration...")
    print(f"🔍 WSGI: Debug mode: {flask_app.debug}")
    print(f"🔍 WSGI: Testing mode: {flask_app.testing}")
    print(f"🔍 WSGI: Secret key set: {bool(flask_app.secret_key)}")
    
    # List all registered routes
    print("🔍 WSGI: Registered routes:")
    for rule in flask_app.url_map.iter_rules():
        print(f"🔍 WSGI: Route: {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
    
    # Check if /api/health route exists
    health_routes = [rule for rule in flask_app.url_map.iter_rules() if '/health' in rule.rule]
    print(f"🔍 WSGI: Health routes found: {len(health_routes)}")
    for route in health_routes:
        print(f"🔍 WSGI: Health route: {route.rule} -> {route.endpoint}")
    
    # Use Flask app directly
    app = flask_app
    print("✅ WSGI: Using Flask app directly for Waitress")
    
    # Test that the app is callable
    if not callable(app):
        raise ValueError("Flask app is not callable - WSGI interface broken")
    
    print("✅ WSGI: Flask app is callable - WSGI interface OK")
    
except ImportError as e:
    print(f"💥 WSGI: Import error: {e}")
    print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")
    
    # Create a simple error app
    def error_app(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        error_html = f"""
        <html><body>
        <h1>Import Error</h1>
        <p>Error: {str(e)}</p>
        <pre>{traceback.format_exc()}</pre>
        </body></html>
        """
        return [error_html.encode('utf-8')]
    
    app = error_app

except Exception as e:
    print(f"💥 WSGI: Unexpected error during app import: {e}")
    print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")
    
    # Create a simple error app
    def error_app(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        error_html = f"""
        <html><body>
        <h1>App Import Error</h1>
        <p>Error: {str(e)}</p>
        <pre>{traceback.format_exc()}</pre>
        </body></html>
        """
        return [error_html.encode('utf-8')]
    
    app = error_app

# Create comprehensive WSGI wrapper for debugging
def debug_wsgi_wrapper(flask_app):
    """Comprehensive WSGI wrapper with detailed logging"""
    def wrapped_app(environ, start_response):
        try:
            method = environ.get('REQUEST_METHOD', 'UNKNOWN')
            path = environ.get('PATH_INFO', '/')
            query = environ.get('QUERY_STRING', '')
            
            print(f"🔍 WSGI: === NEW REQUEST ===")
            print(f"🔍 WSGI: Method: {method}")
            print(f"🔍 WSGI: Path: {path}")
            print(f"🔍 WSGI: Query: {query}")
            print(f"🔍 WSGI: User-Agent: {environ.get('HTTP_USER_AGENT', 'Unknown')}")
            print(f"🔍 WSGI: Remote Addr: {environ.get('REMOTE_ADDR', 'Unknown')}")
            
            # Check if this is a health check request
            if '/health' in path:
                print(f"🔍 WSGI: Health check request detected!")
            
            # Call the Flask app
            print(f"🔍 WSGI: Calling Flask app...")
            result = flask_app(environ, start_response)
            print(f"✅ WSGI: Flask app returned result: {type(result)}")
            
            return result
            
        except Exception as e:
            error_msg = f"WSGI Error: {str(e)}"
            traceback_str = traceback.format_exc()
            
            print(f"💥 WSGI ERROR: {error_msg}")
            print(f"💥 WSGI TRACEBACK:\n{traceback_str}")
            
            # Return error response
            status = '500 Internal Server Error'
            headers = [('Content-Type', 'text/html; charset=utf-8')]
            start_response(status, headers)
            
            error_html = f"""
            <html><body>
            <h1>WSGI Application Error</h1>
            <p><strong>Error:</strong> {error_msg}</p>
            <p><strong>Time:</strong> {datetime.now().isoformat()}</p>
            <hr>
            <h2>Traceback:</h2>
            <pre>{traceback_str}</pre>
            </body></html>
            """
            return [error_html.encode('utf-8')]
    
    return wrapped_app

# Apply debug wrapper if we have a Flask app
if hasattr(app, 'wsgi_app'):
    print("🔍 WSGI: Applying comprehensive debug wrapper...")
    app = debug_wsgi_wrapper(app)
    print("✅ WSGI: Debug wrapper applied")

# Add Flask-level request logging
if hasattr(app, 'before_request') and not callable(app):
    # This means app is the actual Flask instance
    @app.before_request
    def log_flask_request():
        from flask import request
        print(f"🔍 FLASK: === FLASK REQUEST ===")
        print(f"🔍 FLASK: Method: {request.method}")
        print(f"🔍 FLASK: Path: {request.path}")
        print(f"🔍 FLASK: Endpoint: {request.endpoint}")
        print(f"🔍 FLASK: Remote Addr: {request.remote_addr}")

# Server startup logic
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🔍 WSGI: Attempting to start server on port {port}")
    
    # Try Waitress first (production WSGI server)
    try:
        import waitress
        print(f"✅ WSGI: Waitress found and imported successfully!")
        
        # Test the WSGI app before starting server
        print("🔍 WSGI: Testing WSGI app interface...")
        
        # Create a test WSGI environ for /api/health
        test_environ = {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/api/health',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': str(port),
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'http',
            'wsgi.input': None,
            'wsgi.errors': sys.stderr,
            'wsgi.multithread': True,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False,
            'HTTP_USER_AGENT': 'WSGI-Test/1.0',
            'REMOTE_ADDR': '127.0.0.1'
        }
        
        def test_start_response(status, headers):
            print(f"🔍 WSGI: Test response - Status: {status}")
            print(f"🔍 WSGI: Test response - Headers: {headers}")
        
        try:
            print("🔍 WSGI: Testing /api/health endpoint...")
            result = app(test_environ, test_start_response)
            print(f"✅ WSGI: /api/health test successful! Result type: {type(result)}")
            
            # Try to read the response
            if hasattr(result, '__iter__'):
                response_data = b''.join(result)
                print(f"🔍 WSGI: Response data length: {len(response_data)} bytes")
                if len(response_data) < 500:  # Only print if not too long
                    print(f"🔍 WSGI: Response data: {response_data.decode('utf-8', errors='ignore')}")
            
        except Exception as e:
            print(f"💥 WSGI: /api/health test failed: {e}")
            print(f"💥 WSGI: Test traceback:\n{traceback.format_exc()}")
        
        print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
        
        # Start Waitress with the Flask app
        waitress.serve(
            app, 
            host='0.0.0.0', 
            port=port, 
            threads=4, 
            connection_limit=1000,
            cleanup_interval=30,
            channel_timeout=120
        )
        
    except ImportError as e:
        print(f"❌ WSGI: Waitress import failed: {e}")
        print("🔄 WSGI: Using Flask development server as fallback")
        
        # Fallback to Flask development server
        if hasattr(app, 'run'):
            app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
        else:
            print("💥 WSGI: Cannot start any server - app is not a Flask instance")
        
    except Exception as e:
        print(f"💥 WSGI: Server startup error: {e}")
        print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")

print("🔍 WSGI: WSGI module loaded successfully")

