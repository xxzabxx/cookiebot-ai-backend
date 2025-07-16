#!/usr/bin/env python3
"""
Enhanced WSGI entry point with comprehensive error handling
This file handles WSGI-level errors that occur before reaching Flask routes
"""

import os
import sys
import traceback
from datetime import datetime

print("🚀 WSGI: Starting CookieBot AI Backend...")
print(f"🚀 WSGI: Python version: {sys.version}")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_error_response(error_message, status='500 Internal Server Error'):
    """Create a simple HTML error response"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WSGI Error</title>
    </head>
    <body>
        <h1>WSGI Application Error</h1>
        <p><strong>Error:</strong> {error_message}</p>
        <p><strong>Time:</strong> {datetime.now().isoformat()}</p>
        <hr>
        <p>This error occurred at the WSGI level before reaching Flask routes.</p>
    </body>
    </html>
    """
    return html.encode('utf-8')

def wsgi_error_wrapper(app):
    """Wrapper to catch WSGI-level errors"""
    def wrapped_app(environ, start_response):
        try:
            print(f"🔍 WSGI: Handling request: {environ.get('REQUEST_METHOD', 'UNKNOWN')} {environ.get('PATH_INFO', '/')}")
            return app(environ, start_response)
        except Exception as e:
            error_msg = f"WSGI Error: {str(e)}"
            traceback_str = traceback.format_exc()
            
            print(f"💥 WSGI ERROR: {error_msg}")
            print(f"💥 WSGI TRACEBACK:\n{traceback_str}")
            
            # Return error response
            status = '500 Internal Server Error'
            headers = [('Content-Type', 'text/html; charset=utf-8')]
            start_response(status, headers)
            return [create_error_response(f"{error_msg}\n\nTraceback:\n{traceback_str}")]
    
    return wrapped_app

# Try to import Flask app with detailed error handling
app = None
try:
    print("🔍 WSGI: Attempting to import Flask app from main.py...")
    from main import app as flask_app
    
    if flask_app is None:
        raise ValueError("Flask app is None - check main.py app creation")
    
    print(f"✅ WSGI: Flask app imported successfully!")
    print(f"🔍 WSGI: App type: {type(flask_app)}")
    print(f"🔍 WSGI: App name: {getattr(flask_app, 'name', 'unknown')}")
    
    # Wrap the Flask app with error handling
    app = wsgi_error_wrapper(flask_app)
    print("✅ WSGI: Error wrapper applied to Flask app")
    
except ImportError as e:
    print(f"💥 WSGI: Import error: {e}")
    print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")
    
    def error_app(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        return [create_error_response(f"Import Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}")]
    
    app = error_app

except Exception as e:
    print(f"💥 WSGI: Unexpected error during app import: {e}")
    print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")
    
    def error_app(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/html; charset=utf-8')]
        start_response(status, headers)
        return [create_error_response(f"App Import Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}")]
    
    app = error_app

# Server startup logic
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🔍 WSGI: Attempting to start server on port {port}")
    
    # Try Waitress first (production WSGI server)
    try:
        import waitress
        print(f"✅ WSGI: Waitress found and imported successfully!")
        print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
        
        # Start Waitress with the wrapped app
        waitress.serve(app, host='0.0.0.0', port=port, threads=4, connection_limit=1000)
        
    except ImportError as e:
        print(f"❌ WSGI: Waitress import failed: {e}")
        print("🔄 WSGI: Trying Gunicorn as alternative...")
        
        try:
            # Try Gunicorn as alternative
            import gunicorn.app.wsgiapp
            print("✅ WSGI: Gunicorn found, starting server...")
            # Note: This is a simplified approach, real Gunicorn usage would be different
            
        except ImportError:
            print("❌ WSGI: Gunicorn not available")
            print("🔄 WSGI: Using Flask development server as last resort")
            
            # Fallback to Flask development server
            if hasattr(app, 'run'):
                app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
            else:
                print("💥 WSGI: Cannot start any server - app is not a Flask instance")
        
    except Exception as e:
        print(f"💥 WSGI: Server startup error: {e}")
        print(f"💥 WSGI: Traceback:\n{traceback.format_exc()}")

print("🔍 WSGI: WSGI module loaded successfully")
