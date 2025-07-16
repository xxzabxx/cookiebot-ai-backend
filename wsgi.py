#!/usr/bin/env python3
"""
Gunicorn-compatible WSGI entry point
This file ensures proper WSGI application reference for Gunicorn
"""

import os
import sys
import traceback

print("🚀 WSGI: Starting CookieBot AI Backend for Railway...")
print(f"🚀 WSGI: Python version: {sys.version}")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app with detailed error handling
application = None  # Gunicorn looks for 'application' by default
app = None  # Keep 'app' for compatibility

try:
    print("🔍 WSGI: Attempting to import Flask app from main.py...")
    from main import app as flask_app
    
    if flask_app is None:
        raise ValueError("Flask app is None - check main.py app creation")
    
    print(f"✅ WSGI: Flask app imported successfully!")
    print(f"🔍 WSGI: App type: {type(flask_app)}")
    print(f"🔍 WSGI: App name: {getattr(flask_app, 'name', 'unknown')}")
    
    # Set both 'application' and 'app' for maximum compatibility
    application = flask_app  # Gunicorn default
    app = flask_app  # Fallback reference
    
    print("✅ WSGI: Flask app assigned to 'application' variable for Gunicorn")
    
    # Test that the app is callable
    if not callable(application):
        raise ValueError("Flask app is not callable - WSGI interface broken")
    
    print("✅ WSGI: Flask app is callable - WSGI interface OK")
    
    # Test a simple WSGI call to verify it works
    test_environ = {
        'REQUEST_METHOD': 'GET',
        'PATH_INFO': '/',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '8080',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'http',
        'wsgi.input': None,
        'wsgi.errors': sys.stderr,
        'wsgi.multithread': True,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False
    }
    
    def test_start_response(status, headers):
        print(f"🔍 WSGI: Test WSGI call - Status: {status}")
    
    try:
        result = application(test_environ, test_start_response)
        print("✅ WSGI: Test WSGI call successful - application is working")
    except Exception as e:
        print(f"⚠️ WSGI: Test WSGI call failed: {e}")
        print(f"⚠️ WSGI: This might be normal for root path")
    
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
    
    application = error_app
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
    
    application = error_app
    app = error_app

# Server startup logic (only when run directly, not when imported by Gunicorn)
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🔍 WSGI: Railway PORT environment variable: {os.environ.get('PORT', 'not set')}")
    print(f"🔍 WSGI: Using port: {port}")
    
    # Railway-specific environment checks
    railway_env = os.environ.get('RAILWAY_ENVIRONMENT')
    railway_service = os.environ.get('RAILWAY_SERVICE_NAME')
    print(f"🔍 WSGI: Railway environment: {railway_env}")
    print(f"🔍 WSGI: Railway service: {railway_service}")
    
    # Try multiple server options for Railway compatibility
    server_started = False
    
    # Option 1: Try Gunicorn (Railway's preferred WSGI server)
    try:
        import gunicorn.app.wsgiapp as wsgi
        print("✅ WSGI: Gunicorn found - using Railway's preferred WSGI server")
        
        # Configure Gunicorn for Railway with proper WSGI app reference
        sys.argv = [
            'gunicorn',
            '--bind', f'0.0.0.0:{port}',
            '--workers', '1',
            '--worker-class', 'sync',
            '--timeout', '120',
            '--keep-alive', '2',
            '--max-requests', '1000',
            '--max-requests-jitter', '100',
            '--preload',
            '--access-logfile', '-',
            '--error-logfile', '-',
            '--log-level', 'info',
            'wsgi:application'  # Use 'application' instead of 'app'
        ]
        
        print(f"🚀 WSGI: Starting Gunicorn server on 0.0.0.0:{port}")
        print(f"🔍 WSGI: Gunicorn will look for 'wsgi:application'")
        wsgi_app = wsgi.WSGIApplication()
        wsgi_app.run()
        server_started = True
        
    except ImportError:
        print("❌ WSGI: Gunicorn not available")
    except Exception as e:
        print(f"❌ WSGI: Gunicorn failed: {e}")
        print(f"❌ WSGI: Gunicorn traceback:\n{traceback.format_exc()}")
    
    # Option 2: Try Waitress with Railway-optimized settings
    if not server_started:
        try:
            import waitress
            print("✅ WSGI: Using Waitress with Railway-optimized settings")
            
            print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
            
            # Railway-optimized Waitress configuration
            waitress.serve(
                application,  # Use 'application' variable
                host='0.0.0.0', 
                port=port,
                threads=1,
                connection_limit=100,
                cleanup_interval=10,
                channel_timeout=60,
                send_bytes=8192,
                recv_bytes=8192,
                ident='railway-waitress'
            )
            server_started = True
            
        except ImportError:
            print("❌ WSGI: Waitress not available")
        except Exception as e:
            print(f"❌ WSGI: Waitress failed: {e}")
    
    # Option 3: Fallback to Flask development server
    if not server_started:
        try:
            print("🔄 WSGI: Using Flask development server as last resort")
            
            if hasattr(application, 'run'):
                print(f"🚀 WSGI: Starting Flask dev server on 0.0.0.0:{port}")
                application.run(
                    host='0.0.0.0', 
                    port=port, 
                    debug=False, 
                    threaded=True,
                    use_reloader=False,
                    use_debugger=False
                )
                server_started = True
            else:
                print("💥 WSGI: Cannot start Flask dev server - app is not a Flask instance")
                
        except Exception as e:
            print(f"💥 WSGI: Flask dev server failed: {e}")
    
    if not server_started:
        print("💥 WSGI: All server options failed!")
        sys.exit(1)

print("🔍 WSGI: WSGI module loaded successfully")
print(f"🔍 WSGI: Application variable type: {type(application)}")
print(f"🔍 WSGI: Application variable callable: {callable(application)}")

