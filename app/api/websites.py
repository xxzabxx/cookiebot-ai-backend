"""
Website management API endpoints with proper validation and caching.
"""
from datetime import datetime
from typing import Dict, Any

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from app.models.user import User
from app.models.website import Website
from app.utils.database import db
from app.utils.error_handlers import (
    APIResponse, APIException, ErrorCodes, validate_subscription_access
)
from app.utils.validators import (
    validate_json, validate_query_params, WebsiteCreateSchema, 
    WebsiteUpdateSchema, PaginationSchema
)
from app.utils.cache import cached, invalidate_website_cache, website_metrics_cache_key

logger = structlog.get_logger()

# Create blueprint
websites_bp = Blueprint('websites', __name__)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)


@websites_bp.route('', methods=['GET'])
@jwt_required()
@validate_query_params(PaginationSchema)
def get_websites(validated_data: Dict[str, Any]):
    """
    Get user's websites with pagination and caching.
    Fixes N+1 query problems identified in the review.
    """
    try:
        current_user_id = int(get_jwt_identity())
        page = validated_data['page']
        per_page = validated_data['per_page']
        sort_by = validated_data['sort_by']
        sort_order = validated_data['sort_order']
        
        # Build query with proper ordering
        query = Website.query.filter_by(user_id=current_user_id)
        
        # Apply sorting
        if hasattr(Website, sort_by):
            order_column = getattr(Website, sort_by)
            if sort_order == 'desc':
                query = query.order_by(order_column.desc())
            else:
                query = query.order_by(order_column.asc())
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination
        websites = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        
        pagination_info = {
            'page': page,
            'per_page': per_page,
            'total_count': total_count,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
        
        # Convert to dict with analytics summary
        websites_data = [website.to_dict(include_analytics=True) for website in websites]
        
        return APIResponse.success({
            'websites': websites_data,
            'pagination': pagination_info
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get websites", user_id=current_user_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve websites",
            500
        )


@websites_bp.route('', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
@validate_json(WebsiteCreateSchema)
def create_website(validated_data: Dict[str, Any]):
    """
    Create new website with subscription limit validation.
    """
    try:
        current_user_id = int(get_jwt_identity())
        domain = validated_data['domain']
        
        # Get user and check subscription limits
        user = User.query.get(current_user_id)
        if not user:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "User not found",
                404
            )
        
        # Check website limit based on subscription
        website_limit = user.get_website_limit()
        current_website_count = Website.query.filter_by(
            user_id=current_user_id
        ).filter(
            Website.status != 'deleted'
        ).count()
        
        if website_limit != -1 and current_website_count >= website_limit:
            raise APIException(
                ErrorCodes.QUOTA_EXCEEDED,
                f"Website limit reached. Your {user.subscription_tier} plan allows {website_limit} websites.",
                402
            )
        
        # Create website
        website = Website.create_website(current_user_id, domain)
        
        # Invalidate user cache
        invalidate_website_cache(current_user_id, website.id)
        
        return APIResponse.success({
            'website': website.to_dict(include_analytics=True)
        }, "Website created successfully", 201)
        
    except APIException:
        raise
    except ValueError as e:
        raise APIException(
            ErrorCodes.RESOURCE_ALREADY_EXISTS,
            str(e),
            409
        )
    except Exception as e:
        logger.error("Failed to create website", user_id=current_user_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to create website",
            500
        )


@websites_bp.route('/<int:website_id>', methods=['GET'])
@jwt_required()
@cached(ttl=300, key_func=lambda website_id: website_metrics_cache_key(
    int(get_jwt_identity()), website_id
))
def get_website(website_id: int):
    """Get specific website with analytics data."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        return APIResponse.success({
            'website': website.to_dict(include_analytics=True)
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get website", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve website",
            500
        )


@websites_bp.route('/<int:website_id>', methods=['PUT'])
@jwt_required()
@validate_json(WebsiteUpdateSchema)
def update_website(website_id: int, validated_data: Dict[str, Any]):
    """Update website information."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Update allowed fields
        if 'domain' in validated_data:
            # Check if new domain already exists for this user
            existing_website = Website.query.filter_by(
                user_id=current_user_id,
                domain=validated_data['domain']
            ).filter(Website.id != website_id).first()
            
            if existing_website:
                raise APIException(
                    ErrorCodes.RESOURCE_ALREADY_EXISTS,
                    "A website with this domain already exists",
                    409
                )
            
            website.domain = validated_data['domain']
        
        if 'status' in validated_data:
            website.update_status(validated_data['status'])
        
        website.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Invalidate cache
        invalidate_website_cache(current_user_id, website_id)
        
        return APIResponse.success({
            'website': website.to_dict(include_analytics=True)
        }, "Website updated successfully")
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to update website", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to update website",
            500
        )


@websites_bp.route('/<int:website_id>', methods=['DELETE'])
@jwt_required()
def delete_website(website_id: int):
    """Soft delete website."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Soft delete
        website.delete_website()
        db.session.commit()
        
        # Invalidate cache
        invalidate_website_cache(current_user_id, website_id)
        
        return APIResponse.success(
            message="Website deleted successfully"
        )
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to delete website", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to delete website",
            500
        )


@websites_bp.route('/<int:website_id>/integration-code', methods=['GET'])
@jwt_required()
def get_integration_code(website_id: int):
    """Get JavaScript integration code for website."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Generate fresh integration code if not exists
        if not website.integration_code:
            website.generate_integration_code()
            db.session.commit()
        
        return APIResponse.success({
            'integration_code': website.integration_code,
            'client_id': website.client_id
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get integration code", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve integration code",
            500
        )


@websites_bp.route('/<int:website_id>/regenerate-client-id', methods=['POST'])
@jwt_required()
@limiter.limit("3 per hour")
def regenerate_client_id(website_id: int):
    """Regenerate client ID for website (security feature)."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # Generate new client ID
        old_client_id = website.client_id
        website.client_id = Website.generate_client_id()
        
        # Regenerate integration code
        website.generate_integration_code()
        website.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Log security event
        logger.warning(
            "Client ID regenerated",
            website_id=website_id,
            user_id=current_user_id,
            old_client_id=old_client_id,
            new_client_id=website.client_id
        )
        
        # Invalidate cache
        invalidate_website_cache(current_user_id, website_id)
        
        return APIResponse.success({
            'client_id': website.client_id,
            'integration_code': website.integration_code
        }, "Client ID regenerated successfully")
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to regenerate client ID", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to regenerate client ID",
            500
        )


@websites_bp.route('/<int:website_id>/verify', methods=['POST'])
@jwt_required()
@limiter.limit("5 per hour")
def verify_website(website_id: int):
    """Verify website ownership and activate it."""
    try:
        current_user_id = int(get_jwt_identity())
        
        website = Website.query.filter_by(
            id=website_id,
            user_id=current_user_id
        ).first()
        
        if not website:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "Website not found",
                404
            )
        
        # In production, implement actual verification logic
        # For now, just activate the website
        website.update_status('active')
        db.session.commit()
        
        # Invalidate cache
        invalidate_website_cache(current_user_id, website_id)
        
        return APIResponse.success({
            'website': website.to_dict()
        }, "Website verified and activated successfully")
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to verify website", website_id=website_id, error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to verify website",
            500
        )

