"""
Main application entry point for CookieBot.ai.
Replaces the monolithic main.py with a clean, modular structure.
"""
import os
from app import create_app

# Create Flask application
app = create_app(os.getenv('FLASK_ENV', 'production'))

if __name__ == '__main__':
    # Development server
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )

