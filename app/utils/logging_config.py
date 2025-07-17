"""
Structured logging configuration for enhanced monitoring and debugging.
"""
import logging
import sys
from typing import Any, Dict

import structlog
from flask import Flask, request, has_request_context
from flask_jwt_extended import get_jwt_identity


def configure_logging(app: Flask) -> None:
    """Configure structured logging for the application."""
    
    # Configure standard library logging
    logging.basicConfig(
        format=app.config.get('LOG_FORMAT', '%(asctime)s %(levelname)s %(name)s %(message)s'),
        level=getattr(logging, app.config.get('LOG_LEVEL', 'INFO')),
        stream=sys.stdout
    )
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            add_request_context,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer() if app.config.get('FLASK_ENV') == 'production' 
            else structlog.dev.ConsoleRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def add_request_context(logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add request context to log entries."""
    if has_request_context():
        event_dict.update({
            'endpoint': request.endpoint,
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
        })
        
        # Add user ID if available
        try:
            user_id = get_jwt_identity()
            if user_id:
                event_dict['user_id'] = user_id
        except:
            pass  # JWT not available or invalid
    
    return event_dict


class RequestLoggingMiddleware:
    """Middleware for logging HTTP requests and responses."""
    
    def __init__(self, app: Flask):
        self.app = app
        self.logger = structlog.get_logger()
        
        # Register middleware
        app.before_request(self.log_request)
        app.after_request(self.log_response)
    
    def log_request(self):
        """Log incoming requests."""
        # Skip logging for health checks and static files
        if request.endpoint in ['health.health_check', 'static']:
            return
        
        self.logger.info(
            "Request started",
            method=request.method,
            path=request.path,
            content_length=request.content_length,
            content_type=request.content_type
        )
    
    def log_response(self, response):
        """Log outgoing responses."""
        # Skip logging for health checks and static files
        if request.endpoint in ['health.health_check', 'static']:
            return response
        
        self.logger.info(
            "Request completed",
            status_code=response.status_code,
            content_length=response.content_length,
            content_type=response.content_type
        )
        
        return response


def log_security_event(event_type: str, details: Dict[str, Any]) -> None:
    """Log security-related events."""
    logger = structlog.get_logger()
    logger.warning(
        "Security event",
        event_type=event_type,
        **details
    )


def log_business_event(event_type: str, details: Dict[str, Any]) -> None:
    """Log business-related events."""
    logger = structlog.get_logger()
    logger.info(
        "Business event",
        event_type=event_type,
        **details
    )


def log_performance_metric(metric_name: str, value: float, unit: str = 'ms') -> None:
    """Log performance metrics."""
    logger = structlog.get_logger()
    logger.info(
        "Performance metric",
        metric_name=metric_name,
        value=value,
        unit=unit
    )


def setup_logging():
    """Setup basic logging configuration"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)
