"""
Application factory for CookieBot.ai application.
"""

import os
import logging
from flask import Flask
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
    
    # Register error handlers
    register_error_handlers(app)
    
    # Configure CORS
    configure_cors(app)
    
    logger.info("CookieBot.ai application initialized successfully")
    
    return app


def init_extensions(app: Flask) -> None:
    """Initialize Flask extensions."""
    
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
        logger.error("Database initialization failed", error=str(e))
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


def configure_cors(app: Flask) -> None:
    """Configure CORS with secure defaults."""
    origins = app.config.get('CORS_ORIGINS', [])
    
    # Filter out empty strings
    origins = [origin.strip() for origin in origins if origin.strip()]
    
    if not origins:
        # Default origins for development
        origins = [
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

