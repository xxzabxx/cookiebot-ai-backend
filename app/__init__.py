"""
Application factory for CookieBot.ai application.
"""

import os
import logging
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config.settings import get_config
from .utils.database import init_database
from .utils.error_handlers import register_error_handlers
from .utils.logging_config import setup_logging


def create_app(config_name: str = None) -> Flask:
    """Create and configure Flask application."""
    
    # Setup logging first
    setup_logging()
    logger = logging.getLogger(__name__)
    
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')
    config = get_config(config_name)
    app.config.from_object(config)
    
    logger.info(f"Starting CookieBot.ai application in {config_name} mode")
    
    # Initialize extensions
    init_extensions(app)
    
    # Initialize database
    init_database_tables(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register static file serving route
    register_static_routes(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Configure CORS
    configure_cors(app)
    
    logger.info("CookieBot.ai application initialized successfully")
    
    return app


def init_extensions(app: Flask) -> None:
    """Initialize Flask extensions."""
    
    # Initialize SQLAlchemy with app
    from .utils.database import db
    db.init_app(app)
    
    # JWT Manager
    jwt = JWTManager(app)
    
    # Rate Limiter
    limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["1000 per hour"]
)

    
    # Store extensions in app for access
    app.jwt = jwt
    app.limiter = limiter


def init_database_tables(app: Flask) -> None:
    """Initialize database tables."""
    try:
        from .utils.database_schema import create_all_tables, add_missing_columns
        from .utils.database import get_db_connection
        
        with app.app_context():
            conn = get_db_connection()
            if conn:
                # Create all tables
                create_all_tables(conn)
                
                # Add any missing columns to existing tables
                add_missing_columns(conn)
                
                conn.close()
                logging.info("Database tables initialized successfully")
            else:
                logging.error("Failed to connect to database")
                
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Database initialization failed: {str(e)}")
        raise


def register_blueprints(app: Flask) -> None:
    """Register all application blueprints."""
    
    # Import all blueprints
    from .api.auth import auth_bp
    from .api.websites import websites_bp
    from .api.analytics import analytics_bp
    from .api.public import public_bp
    from .api.health import health_bp
    from .api.compliance import compliance_bp
    from .api.privacy_insights import privacy_insights_bp
    from .api.contact import contact_bp
    from .api.billing import billing_bp
    
    # Register all blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(websites_bp, url_prefix='/api/websites')
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    app.register_blueprint(public_bp, url_prefix='/api/public')
    app.register_blueprint(health_bp, url_prefix='/api/health')
    app.register_blueprint(compliance_bp, url_prefix='/api/compliance')
    app.register_blueprint(privacy_insights_bp, url_prefix='/api/privacy-insights')
    app.register_blueprint(contact_bp, url_prefix='/api/contact')
    app.register_blueprint(billing_bp, url_prefix='/api/billing')


def register_static_routes(app: Flask) -> None:
    """Register static file serving routes for V3 script and other assets."""
    
    @app.route('/static/<path:filename>')
    @app.route('/static/<path:filename>/')
    def serve_static(filename):
        """Serve static files including the V3 cookie script - DIAGNOSTIC VERSION."""
        try:
            # DIAGNOSTIC: Log detailed path information
            app.logger.info(f"=== STATIC FILE DIAGNOSTIC ===")
            app.logger.info(f"Requested file: {filename}")
            app.logger.info(f"Current working directory: {os.getcwd()}")
            app.logger.info(f"__file__ location: {__file__}")
            app.logger.info(f"App root path: {app.root_path}")
            
            # Test multiple possible static directory locations
            possible_static_dirs = [
                os.path.join(os.getcwd(), 'static'),  # Current working directory
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'),  # Relative to app
                os.path.join(app.root_path, 'static'),  # Relative to Flask app root
                '/app/static',  # Absolute path for Railway
                'static',  # Simple relative path
                '/static',  # Root static
                os.path.join(os.path.dirname(__file__), '..', 'static'),  # Another relative attempt
            ]
            
            app.logger.info(f"Testing {len(possible_static_dirs)} possible static directories:")
            
            for i, static_dir in enumerate(possible_static_dirs):
                app.logger.info(f"  {i+1}. Testing: {static_dir}")
                app.logger.info(f"     Exists: {os.path.exists(static_dir)}")
                
                if os.path.exists(static_dir):
                    # List contents of the directory
                    try:
                        contents = os.listdir(static_dir)
                        app.logger.info(f"     Contents: {contents}")
                        
                        # Check if our specific file exists
                        file_path = os.path.join(static_dir, filename)
                        file_exists = os.path.exists(file_path)
                        app.logger.info(f"     File '{filename}' exists: {file_exists}")
                        
                        if file_exists:
                            app.logger.info(f"SUCCESS: Found file at {file_path}")
                            
                            # Serve the file with proper CORS headers
                            response = send_from_directory(static_dir, filename)
                            
                            # Add CORS headers for script files
                            if filename.endswith('.js'):
                                response.headers['Access-Control-Allow-Origin'] = '*'
                                response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
                                response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                                response.headers['Content-Type'] = 'application/javascript'
                            
                            return response
                            
                    except Exception as e:
                        app.logger.error(f"     Error listing directory: {str(e)}")
                else:
                    app.logger.info(f"     Directory does not exist")
            
            # If we get here, file was not found in any directory
            app.logger.error(f"FAILED: File '{filename}' not found in any static directory")
            
            # Return detailed diagnostic information
            return jsonify({
                "error": {
                    "code": "STATIC_DIAGNOSTIC",
                    "message": f"Static file '{filename}' not found",
                    "diagnostic": {
                        "requested_file": filename,
                        "current_working_directory": os.getcwd(),
                        "app_root_path": app.root_path,
                        "tested_directories": possible_static_dirs,
                        "existing_directories": [d for d in possible_static_dirs if os.path.exists(d)]
                    }
                },
                "success": False
            }), 404
            
        except Exception as e:
            app.logger.error(f"EXCEPTION in static file serving: {str(e)}")
            return jsonify({
                "error": {
                    "code": "STATIC_ERROR", 
                    "message": f"Internal server error while serving static file: {str(e)}"
                },
                "success": False
            }), 500


def configure_cors(app: Flask) -> None:
    """Configure CORS with secure defaults."""
    origins = app.config.get('CORS_ORIGINS', [])
    
    # Filter out empty strings
    origins = [origin.strip() for origin in origins if origin.strip()]
    
    if not origins:
        # Default origins for development
        origins = [
            "https://cookiebotai.netlify.app",
            'http://localhost:3000',
            'http://localhost:3001',
            'https://cookiebot.ai',
            'https://www.cookiebot.ai'
        ]
    
    CORS(app, 
         origins=origins,
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])


# Create application instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)

