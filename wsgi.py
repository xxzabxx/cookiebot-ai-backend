#!/usr/bin/env python3
"""
Fixed WSGI entry point - Direct Flask app serving
This file fixes the Waitress ↔ WSGI interface issue
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
    
    # Use Flask app directly (no wrapper for now)
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

# Add simple request logging to Flask app
if hasattr(app, 'before_request'):
    @app.before_request
    def log_request():
        from flask import request
        print(f"🔍 FLASK: Handling request: {request.method} {request.path}")

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
        
        # Create a test WSGI environ
        test_environ = {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/test',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': str(port),
            'wsgi.version': (1, 0),
            'wsgi.url_scheme': 'http',
            'wsgi.input': None,
            'wsgi.errors': sys.stderr,
            'wsgi.multithread': True,
            'wsgi.multiprocess': False,
            'wsgi.run_once': False
        }
        
        def test_start_response(status, headers):
            print(f"🔍 WSGI: Test response - Status: {status}")
        
        try:
            result = app(test_environ, test_start_response)
            print("✅ WSGI: WSGI app test successful!")
        except Exception as e:
            print(f"💥 WSGI: WSGI app test failed: {e}")
            print(f"💥 WSGI: Test traceback:\n{traceback.format_exc()}")
        
        print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
        
        # Start Waitress with the Flask app directly
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

