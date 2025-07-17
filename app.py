"""
Main application entry point for CookieBot.ai.
Replaces the monolithic main.py with a clean, modular structure.
"""
import os
from app import create_app
# Create Flask application
app = create_app(os.getenv('FLASK_ENV', 'production' ))
# Always run the server (Railway needs this)
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=os.getenv('FLASK_ENV') == 'development'
    )
else:
    # For production WSGI servers
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=False
    )
