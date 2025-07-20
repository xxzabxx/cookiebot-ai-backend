"""
Application factory for CookieBot.ai application.
"""
import os
import logging
from flask import Flask, send_from_directory
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
    
    # Create Flask app with static file configuration
    app = Flask(__name__, 
                static_folder='../static',  # Points to /static from /app
                static_url_path='/static')
    
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
    
    # Register static file serving route (backup method)
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
        app=app,
        key_func=get_remote_address,
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
                raise
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
    @app.route('/static/<path:filename>/')  # Handle both with and without trailing slash
    def serve_static(filename):
        """Serve static files including the V3 cookie script."""
        try:
            # Use multiple possible static directory locations
            possible_static_dirs = [
                os.path.join(os.getcwd(), 'static'),  # Current working directory
                os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static'),  # Relative to app
                '/app/static',  # Absolute path for Railway
                'static'  # Simple relative path
            ]
            
            static_dir = None
            for dir_path in possible_static_dirs:
                if os.path.exists(dir_path):
                    static_dir = dir_path
                    break
            
            if not static_dir:
                app.logger.error(f"Static directory not found. Checked: {possible_static_dirs}")
                return {"error": {"code": "STATIC_001", "message": "Static directory not found"}}, 404
            
            # Log the request for debugging
            app.logger.info(f"Serving static file: {filename} from {static_dir}")
            
            # Serve the file with proper CORS headers
            response = send_from_directory(static_dir, filename)
            
            # Add CORS headers for script files
            if filename.endswith('.js'):
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
                response.headers['Content-Type'] = 'application/javascript'
            
            return response
            
        except FileNotFoundError:
            app.logger.warning(f"Static file not found: {filename}")
            return {"error": {"code": "STATIC_002", "message": f"File not found: {filename}"}}, 404
        except Exception as e:
            app.logger.error(f"Error serving static file {filename}: {str(e)}")
            return {"error": {"code": "STATIC_003", "message": "Internal server error"}}, 500


def configure_cors(app: Flask) -> None:
    """Configure CORS for the application."""
    CORS(app, 
         origins=[
             "https://cookiebotai.netlify.app",
             "https://cookiebot.ai",
             "http://localhost:3000",
             "http://localhost:5173"
         ],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         allow_headers=["Content-Type", "Authorization"])

