#!/usr/bin/env python3
"""
Platform-agnostic WSGI entry point
This file uses the most standard approach that works across all platforms
"""

import os
import sys

print("🚀 WSGI: Starting CookieBot AI Backend - Platform Agnostic...")

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app directly
try:
    print("🔍 WSGI: Importing Flask app from main.py...")
    from main import app
    
    if app is None:
        raise ValueError("Flask app is None")
    
    print(f"✅ WSGI: Flask app imported successfully")
    print(f"🔍 WSGI: App type: {type(app)}")
    
    # Standard WSGI application variable
    application = app
    
    print("✅ WSGI: Application ready for WSGI serving")
    
except Exception as e:
    print(f"💥 WSGI: Failed to import Flask app: {e}")
    
    # Create minimal error application
    def application(environ, start_response):
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/plain')]
        start_response(status, headers)
        return [f"Error importing Flask app: {str(e)}".encode('utf-8')]

# Direct server startup for testing
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    print(f"🚀 WSGI: Starting server on port {port}")
    
    # Use the simplest possible approach
    try:
        # Try Waitress first (most compatible)
        import waitress
        print("✅ WSGI: Using Waitress")
        waitress.serve(application, host='0.0.0.0', port=port)
        
    except ImportError:
        print("🔄 WSGI: Waitress not available, using Flask built-in")
        # Fallback to Flask's built-in server
        app.run(host='0.0.0.0', port=port, debug=False)

print("🔍 WSGI: Module loaded")

