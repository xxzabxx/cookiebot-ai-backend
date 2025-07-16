#!/usr/bin/env python3
"""
WSGI Entry Point for Railway Deployment
This file tells Railway how to start the application with a production server
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import the Flask app from main.py
from main import app

print("🚀 WSGI: Starting CookieBot AI Backend...")
print(f"🚀 WSGI: Python version: {sys.version}")

# Configure for production
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 WSGI: Attempting to start server on port {port}")
    
    # Try Waitress first (production WSGI server)
    try:
        import waitress
        print(f"✅ WSGI: Waitress found! Version: {waitress.__version__}")
        print(f"🚀 WSGI: Starting Waitress server on 0.0.0.0:{port}")
        waitress.serve(app, host='0.0.0.0', port=port, threads=4, connection_limit=1000)
        
    except ImportError as e:
        print(f"❌ WSGI: Waitress import failed: {e}")
        
        # Try Gunicorn as backup
        try:
            import gunicorn
            print(f"✅ WSGI: Trying Gunicorn as alternative...")
            # This would need gunicorn CLI setup
            
        except ImportError:
            print(f"❌ WSGI: Gunicorn not available")
            print("🔄 WSGI: Using Flask development server as last resort")
            app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
            
    except Exception as e:
        print(f"💥 WSGI: Unexpected error: {e}")
        print("🔄 WSGI: Using Flask development server as last resort")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

# For WSGI servers (like Gunicorn) that import this file
application = app

if __name__ != "__main__":
    print("🔍 WSGI: Imported as module for WSGI server")

