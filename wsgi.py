#!/usr/bin/env python3
"""
WSGI Entry Point for Railway Deployment
This file tells Railway how to start the application with a production server
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

print("🚀 WSGI: Starting CookieBot AI Backend...")
print(f"🚀 WSGI: Python version: {sys.version}")

# Configure for production
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 WSGI: Attempting to start server on port {port}")
    
    # Try to import the Flask app with detailed error handling
    try:
        print("🔍 WSGI: Attempting to import Flask app from main.py...")
        from main import app
        print("✅ WSGI: Flask app imported successfully!")
        
        # Verify the app is a Flask instance
        print(f"🔍 WSGI: App type: {type(app)}")
        print(f"🔍 WSGI: App name: {app.name}")
        
    except ImportError as e:
        print(f"❌ WSGI: Import error: {e}")
        print("💥 WSGI: Failed to import Flask app from main.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ WSGI: Unexpected error during import: {e}")
        print("💥 WSGI: Failed to import Flask app")
        sys.exit(1)
    
    # Try Waitress first (production WSGI server)
    try:
        import waitress
        print("✅ WSGI: Waitress found and imported successfully!")
        print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
        waitress.serve(app, host='0.0.0.0', port=port, threads=4, connection_limit=1000)
        
    except ImportError as e:
        print(f"❌ WSGI: Waitress import failed: {e}")
        print("🔄 WSGI: Trying Gunicorn as alternative...")
        
        try:
            # Try Gunicorn as alternative
            import gunicorn.app.wsgiapp as wsgi
            print("✅ WSGI: Gunicorn found, starting server...")
            sys.argv = ['gunicorn', '--bind', f'0.0.0.0:{port}', '--workers', '1', 'main:app']
            wsgi.run()
            
        except ImportError:
            print("❌ WSGI: Gunicorn not available")
            print("🔄 WSGI: Using Flask development server as last resort")
            app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
            
    except Exception as e:
        print(f"💥 WSGI: Waitress error: {e}")
        print("🔄 WSGI: Using Flask development server as last resort")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# For direct WSGI server usage (if needed)
try:
    from main import app as application
except ImportError as e:
    print(f"❌ WSGI: Could not import Flask app: {e}")
    application = None

