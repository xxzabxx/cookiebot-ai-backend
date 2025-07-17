"""
Health check endpoints for monitoring and deployment.
"""
from datetime import datetime

from flask import Blueprint
from sqlalchemy import text

from app.utils.database import db
from app.utils.error_handlers import APIResponse
from app.utils.cache import cache_manager

health_bp = Blueprint('health', __name__)


@health_bp.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    return APIResponse.success({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'cookiebot-api'
    })


@health_bp.route('/health/detailed', methods=['GET'])
def detailed_health_check():
    """Detailed health check with dependency status."""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'cookiebot-api',
        'dependencies': {}
    }
    
    # Check database
    try:
        db.session.execute(text('SELECT 1'))
        health_status['dependencies']['database'] = 'healthy'
    except Exception as e:
        health_status['dependencies']['database'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Check cache
    try:
        cache_manager.set('health_check', 'test', 10)
        result = cache_manager.get('health_check')
        if result == 'test':
            health_status['dependencies']['cache'] = 'healthy'
        else:
            health_status['dependencies']['cache'] = 'unhealthy: cache test failed'
            health_status['status'] = 'degraded'
    except Exception as e:
        health_status['dependencies']['cache'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'degraded'
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    
    return APIResponse.success(health_status, status_code=status_code)

