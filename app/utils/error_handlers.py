"""
Secure error handling system that fixes information disclosure issues.
Implements standardized error responses and proper logging.
"""
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from flask import Flask, jsonify, request
from flask_jwt_extended.exceptions import JWTExtendedException
from marshmallow import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException
import structlog

logger = structlog.get_logger()


class ErrorCodes:
    """Standardized error codes for consistent client-side handling."""
    
    # Authentication errors (1000-1099)
    INVALID_CREDENTIALS = "AUTH_001"
    TOKEN_EXPIRED = "AUTH_002"
    TOKEN_INVALID = "AUTH_003"
    INSUFFICIENT_PERMISSIONS = "AUTH_004"
    ACCOUNT_LOCKED = "AUTH_005"
    
    # Validation errors (1100-1199)
    VALIDATION_ERROR = "VAL_001"
    MISSING_REQUIRED_FIELD = "VAL_002"
    INVALID_FORMAT = "VAL_003"
    INVALID_EMAIL = "VAL_004"
    PASSWORD_TOO_WEAK = "VAL_005"
    
    # Resource errors (1200-1299)
    RESOURCE_NOT_FOUND = "RES_001"
    RESOURCE_ALREADY_EXISTS = "RES_002"
    RESOURCE_CONFLICT = "RES_003"
    RESOURCE_FORBIDDEN = "RES_004"
    
    # System errors (1300-1399)
    DATABASE_ERROR = "SYS_001"
    EXTERNAL_SERVICE_ERROR = "SYS_002"
    RATE_LIMIT_EXCEEDED = "SYS_003"
    INTERNAL_ERROR = "SYS_004"
    SERVICE_UNAVAILABLE = "SYS_005"
    
    # Business logic errors (1400-1499)
    SUBSCRIPTION_REQUIRED = "BIZ_001"
    QUOTA_EXCEEDED = "BIZ_002"
    PAYMENT_REQUIRED = "BIZ_003"
    FEATURE_DISABLED = "BIZ_004"


class APIException(Exception):
    """Custom exception for API errors with structured error information."""
    
    def __init__(
        self, 
        code: str, 
        message: str, 
        status_code: int = 400, 
        details: Optional[Dict] = None
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


class APIResponse:
    """Standardized API response formatter."""
    
    @staticmethod
    def success(
        data: Any = None, 
        message: Optional[str] = None, 
        status_code: int = 200
    ) -> Tuple[Dict, int]:
        """Create standardized success response."""
        response = {
            "success": True,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        if data is not None:
            response["data"] = data
        if message:
            response["message"] = message
            
        return response, status_code
    
    @staticmethod
    def error(
        code: str, 
        message: str, 
        details: Optional[Dict] = None, 
        status_code: int = 400
    ) -> Tuple[Dict, int]:
        """Create standardized error response."""
        response = {
            "success": False,
            "error": {
                "code": code,
                "message": message
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        if details:
            response["error"]["details"] = details
            
        return response, status_code


def register_error_handlers(app: Flask) -> None:
    """Register all error handlers with the Flask app."""
    
    @app.errorhandler(APIException)
    def handle_api_exception(error: APIException):
        """Handle custom API exceptions."""
        logger.error(
            "API Exception occurred",
            error_code=error.code,
            message=error.message,
            details=error.details,
            endpoint=request.endpoint,
            method=request.method,
            user_agent=request.headers.get('User-Agent'),
            ip_address=request.remote_addr
        )
        
        return jsonify(APIResponse.error(
            error.code, 
            error.message, 
            error.details, 
            error.status_code
        )[0]), error.status_code
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(error: ValidationError):
        """Handle Marshmallow validation errors."""
        logger.warning(
            "Validation error occurred",
            validation_errors=error.messages,
            endpoint=request.endpoint
        )
        
        return jsonify(APIResponse.error(
            ErrorCodes.VALIDATION_ERROR,
            "Request validation failed",
            {"validation_errors": error.messages},
            422
        )[0]), 422
    
    @app.errorhandler(JWTExtendedException)
    def handle_jwt_exceptions(error: JWTExtendedException):
        """Handle JWT-related errors."""
        logger.warning(
            "JWT error occurred",
            error_type=type(error).__name__,
            message=str(error),
            endpoint=request.endpoint
        )
        
        # Map JWT exceptions to our error codes
        error_mapping = {
            'ExpiredSignatureError': (ErrorCodes.TOKEN_EXPIRED, "Token has expired"),
            'InvalidTokenError': (ErrorCodes.TOKEN_INVALID, "Invalid token"),
            'NoAuthorizationError': (ErrorCodes.TOKEN_INVALID, "Authorization header required"),
            'InvalidHeaderError': (ErrorCodes.TOKEN_INVALID, "Invalid authorization header"),
        }
        
        error_type = type(error).__name__
        code, message = error_mapping.get(error_type, (ErrorCodes.TOKEN_INVALID, "Authentication failed"))
        
        return jsonify(APIResponse.error(code, message, status_code=401)[0]), 401
    
    @app.errorhandler(SQLAlchemyError)
    def handle_database_error(error: SQLAlchemyError):
        """Handle database errors without exposing internal details."""
        logger.error(
            "Database error occurred",
            error_type=type(error).__name__,
            error_message=str(error),
            endpoint=request.endpoint,
            method=request.method
        )
        
        # Never expose database details to users
        return jsonify(APIResponse.error(
            ErrorCodes.DATABASE_ERROR,
            "A database error occurred. Please try again later.",
            status_code=500
        )[0]), 500
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        """Handle standard HTTP exceptions."""
        logger.warning(
            "HTTP exception occurred",
            status_code=error.code,
            description=error.description,
            endpoint=request.endpoint
        )
        
        # Map HTTP status codes to our error codes
        status_code_mapping = {
            400: ErrorCodes.VALIDATION_ERROR,
            401: ErrorCodes.INVALID_CREDENTIALS,
            403: ErrorCodes.INSUFFICIENT_PERMISSIONS,
            404: ErrorCodes.RESOURCE_NOT_FOUND,
            405: ErrorCodes.VALIDATION_ERROR,
            409: ErrorCodes.RESOURCE_CONFLICT,
            413: ErrorCodes.VALIDATION_ERROR,
            429: ErrorCodes.RATE_LIMIT_EXCEEDED,
        }
        
        code = status_code_mapping.get(error.code, ErrorCodes.INTERNAL_ERROR)
        
        return jsonify(APIResponse.error(
            code,
            error.description or "An error occurred",
            status_code=error.code
        )[0]), error.code
    
    @app.errorhandler(Exception)
    def handle_generic_exception(error: Exception):
        """Handle any unhandled exceptions."""
        logger.error(
            "Unhandled exception occurred",
            error_type=type(error).__name__,
            error_message=str(error),
            endpoint=request.endpoint,
            method=request.method,
            exc_info=True
        )
        
        # Never expose internal error details to users
        return jsonify(APIResponse.error(
            ErrorCodes.INTERNAL_ERROR,
            "An internal error occurred. Please try again later.",
            status_code=500
        )[0]), 500
    
    @app.errorhandler(413)
    def handle_request_entity_too_large(error):
        """Handle request size limit exceeded."""
        return jsonify(APIResponse.error(
            ErrorCodes.VALIDATION_ERROR,
            "Request entity too large",
            {"max_size": "16MB"},
            413
        )[0]), 413
    
    @app.errorhandler(429)
    def handle_rate_limit_exceeded(error):
        """Handle rate limit exceeded."""
        return jsonify(APIResponse.error(
            ErrorCodes.RATE_LIMIT_EXCEEDED,
            "Rate limit exceeded. Please try again later.",
            status_code=429
        )[0]), 429


def log_security_event(event_type: str, details: Dict[str, Any]) -> None:
    """Log security-related events for monitoring."""
    logger.warning(
        "Security event detected",
        event_type=event_type,
        details=details,
        endpoint=request.endpoint if request else None,
        method=request.method if request else None,
        ip_address=request.remote_addr if request else None,
        user_agent=request.headers.get('User-Agent') if request else None
    )


def require_admin(f):
    """Decorator to require admin privileges."""
    from functools import wraps
    from flask_jwt_extended import get_jwt_identity
    from app.models.user import User
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_user_id = get_jwt_identity()
            if not current_user_id:
                raise APIException(
                    ErrorCodes.INVALID_CREDENTIALS,
                    "Authentication required",
                    401
                )
            
            user = User.query.get(current_user_id)
            if not user or not user.is_admin:
                log_security_event("unauthorized_admin_access", {
                    "user_id": current_user_id,
                    "endpoint": request.endpoint
                })
                raise APIException(
                    ErrorCodes.INSUFFICIENT_PERMISSIONS,
                    "Admin privileges required",
                    403
                )
            
            return f(*args, **kwargs)
            
        except APIException:
            raise
        except Exception as e:
            logger.error("Admin check failed", error=str(e))
            raise APIException(
                ErrorCodes.INTERNAL_ERROR,
                "Authorization check failed",
                500
            )
    
    return decorated_function


def validate_subscription_access(required_tier: str = 'free'):
    """Decorator to validate subscription access."""
    from functools import wraps
    from flask_jwt_extended import get_jwt_identity
    from app.models.user import User
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                current_user_id = get_jwt_identity()
                if not current_user_id:
                    raise APIException(
                        ErrorCodes.INVALID_CREDENTIALS,
                        "Authentication required",
                        401
                    )
                
                user = User.query.get(current_user_id)
                if not user:
                    raise APIException(
                        ErrorCodes.RESOURCE_NOT_FOUND,
                        "User not found",
                        404
                    )
                
                # Check subscription tier
                tier_hierarchy = ['free', 'basic', 'pro', 'enterprise']
                user_tier_level = tier_hierarchy.index(user.subscription_tier)
                required_tier_level = tier_hierarchy.index(required_tier)
                
                if user_tier_level < required_tier_level:
                    raise APIException(
                        ErrorCodes.SUBSCRIPTION_REQUIRED,
                        f"This feature requires {required_tier} subscription or higher",
                        402
                    )
                
                return f(*args, **kwargs)
                
            except APIException:
                raise
            except Exception as e:
                logger.error("Subscription check failed", error=str(e))
                raise APIException(
                    ErrorCodes.INTERNAL_ERROR,
                    "Subscription validation failed",
                    500
                )
        
        return decorated_function
    return decorator


def handle_api_error(error, message="An error occurred"):
    """Handle API errors with proper logging and response"""
    import logging
    from flask import jsonify
    
    logger = logging.getLogger(__name__)
    logger.error(f"{message}: {str(error)}")
    
    return jsonify({'error': message}), 500
