"""
Authentication API endpoints with enhanced security.
Fixes JWT and authentication issues identified in the review.
"""
from datetime import datetime, timedelta
from typing import Dict, Any

from flask import Blueprint, request
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog

from app.models.user import User
from app.utils.database import db
from app.utils.error_handlers import APIResponse, APIException, ErrorCodes, log_security_event
from app.utils.validators_debug import (
    validate_json, UserRegistrationSchema, UserLoginSchema,
    PasswordResetRequestSchema, PasswordResetSchema
)
from app.utils.cache import cache_manager

logger = structlog.get_logger()

# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Rate limiting for auth endpoints
limiter = Limiter(key_func=get_remote_address)


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
@validate_json(UserRegistrationSchema)
def register(validated_data: Dict[str, Any]):
    """
    Register new user with enhanced security validation.
    
    Fixes:
    - Proper input validation
    - Secure password hashing
    - Duplicate email checking
    - Proper error handling without information disclosure
    """
    try:
        # Extract validated data
        email = validated_data['email']
        password = validated_data['password']
        first_name = validated_data['first_name']
        last_name = validated_data['last_name']
        company = validated_data.get('company')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email.lower()).first()
        if existing_user:
            raise APIException(
                ErrorCodes.RESOURCE_ALREADY_EXISTS,
                "An account with this email already exists",
                409
            )
        
        # Create new user
        user = User.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            company=company
        )
        
        # Create access and refresh tokens
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(hours=1)
        )
        refresh_token = create_refresh_token(
            identity=str(user.id),
            expires_delta=timedelta(days=30)
        )
        
        # Log successful registration
        logger.info(
            "User registered successfully",
            user_id=user.id,
            email=user.email,
            ip_address=request.remote_addr
        )
        
        return APIResponse.success({
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }, "Registration successful", 201)
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Registration failed", error=str(e), email=validated_data.get('email'))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Registration failed. Please try again later.",
            500
        )


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
@validate_json(UserLoginSchema)
def login(validated_data: Dict[str, Any]):
    """
    Authenticate user with enhanced security measures.
    
    Fixes:
    - Account lockout mechanism
    - Failed attempt tracking
    - Secure token generation
    - Proper error handling
    """
    try:
        email = validated_data['email']
        password = validated_data['password']
        ip_address = request.remote_addr
        
        # Authenticate user
        user = User.authenticate(email, password, ip_address)
        
        if not user:
            # Log failed login attempt
            log_security_event("failed_login", {
                "email": email,
                "ip_address": ip_address,
                "user_agent": request.headers.get('User-Agent')
            })
            
            raise APIException(
                ErrorCodes.INVALID_CREDENTIALS,
                "Invalid email or password",
                401
            )
        
        # Check if account is locked
        if user.is_account_locked():
            log_security_event("locked_account_access", {
                "user_id": user.id,
                "email": user.email,
                "ip_address": ip_address
            })
            
            raise APIException(
                ErrorCodes.ACCOUNT_LOCKED,
                "Account is temporarily locked due to multiple failed login attempts",
                423
            )
        
        # Create tokens
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(hours=1)
        )
        refresh_token = create_refresh_token(
            identity=str(user.id),
            expires_delta=timedelta(days=30)
        )
        
        # Log successful login
        logger.info(
            "User logged in successfully",
            user_id=user.id,
            email=user.email,
            ip_address=ip_address
        )
        
        return APIResponse.success({
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }, "Login successful")
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e), email=validated_data.get('email'))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Login failed. Please try again later.",
            500
        )


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh access token using refresh token.
    
    Fixes:
    - Proper token refresh mechanism
    - Security validation
    """
    try:
        current_user_id = get_jwt_identity()
        
        # Verify user still exists and is active
        user = User.query.get(current_user_id)
        if not user or not user.is_active:
            raise APIException(
                ErrorCodes.INVALID_CREDENTIALS,
                "User account not found or inactive",
                401
            )
        
        # Create new access token
        new_access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(hours=1)
        )
        
        logger.info("Token refreshed", user_id=user.id)
        
        return APIResponse.success({
            'access_token': new_access_token
        }, "Token refreshed successfully")
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Token refresh failed",
            500
        )


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout user and invalidate token.
    
    Note: In a production environment, you would want to implement
    token blacklisting using Redis or database storage.
    """
    try:
        current_user_id = get_jwt_identity()
        jti = get_jwt()['jti']  # JWT ID for blacklisting
        
        # In production, add token to blacklist
        # blacklist_token(jti)
        
        logger.info("User logged out", user_id=current_user_id)
        
        return APIResponse.success(
            message="Logged out successfully"
        )
        
    except Exception as e:
        logger.error("Logout failed", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Logout failed",
            500
        )


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user information."""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get(current_user_id)
        if not user:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "User not found",
                404
            )
        
        return APIResponse.success({
            'user': user.to_dict()
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Failed to get current user", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to retrieve user information",
            500
        )


@auth_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    """Update current user information."""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get(current_user_id)
        if not user:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "User not found",
                404
            )
        
        # Get update data
        data = request.get_json() or {}
        
        # Update allowed fields
        if 'first_name' in data:
            user.first_name = data['first_name'].strip()
        if 'last_name' in data:
            user.last_name = data['last_name'].strip()
        if 'company' in data:
            user.company = data['company'].strip() if data['company'] else None
        
        user.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Invalidate user cache
        cache_manager.delete(f"user:{user.id}")
        
        logger.info("User profile updated", user_id=user.id)
        
        return APIResponse.success({
            'user': user.to_dict()
        }, "Profile updated successfully")
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Failed to update user", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Failed to update profile",
            500
        )


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
@limiter.limit("3 per minute")
def change_password():
    """Change user password with security validation."""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json() or {}
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            raise APIException(
                ErrorCodes.VALIDATION_ERROR,
                "Current password and new password are required",
                400
            )
        
        user = User.query.get(current_user_id)
        if not user:
            raise APIException(
                ErrorCodes.RESOURCE_NOT_FOUND,
                "User not found",
                404
            )
        
        # Verify current password
        if not user.check_password(current_password):
            log_security_event("invalid_password_change", {
                "user_id": user.id,
                "ip_address": request.remote_addr
            })
            
            raise APIException(
                ErrorCodes.INVALID_CREDENTIALS,
                "Current password is incorrect",
                401
            )
        
        # Validate new password (basic validation here, full validation in schema)
        if len(new_password) < 8:
            raise APIException(
                ErrorCodes.PASSWORD_TOO_WEAK,
                "New password must be at least 8 characters long",
                400
            )
        
        # Set new password
        user.set_password(new_password)
        db.session.commit()
        
        logger.info("Password changed successfully", user_id=user.id)
        
        return APIResponse.success(
            message="Password changed successfully"
        )
        
    except APIException:
        raise
    except Exception as e:
        db.session.rollback()
        logger.error("Password change failed", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Password change failed",
            500
        )


@auth_bp.route('/request-password-reset', methods=['POST'])
@limiter.limit("3 per hour")
@validate_json(PasswordResetRequestSchema)
def request_password_reset(validated_data: Dict[str, Any]):
    """Request password reset email."""
    try:
        email = validated_data['email']
        
        user = User.query.filter_by(email=email.lower()).first()
        
        # Always return success to prevent email enumeration
        # but only send email if user exists
        if user and user.is_active:
            # In production, generate secure reset token and send email
            # reset_token = generate_reset_token(user.id)
            # send_password_reset_email(user.email, reset_token)
            
            logger.info("Password reset requested", user_id=user.id, email=user.email)
        else:
            logger.warning("Password reset requested for non-existent user", email=email)
        
        return APIResponse.success(
            message="If an account with this email exists, a password reset link has been sent"
        )
        
    except Exception as e:
        logger.error("Password reset request failed", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Password reset request failed",
            500
        )


@auth_bp.route('/verify-token', methods=['POST'])
@jwt_required()
def verify_token():
    """Verify if current token is valid."""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get(current_user_id)
        if not user or not user.is_active:
            raise APIException(
                ErrorCodes.INVALID_CREDENTIALS,
                "Invalid token",
                401
            )
        
        return APIResponse.success({
            'valid': True,
            'user_id': user.id
        })
        
    except APIException:
        raise
    except Exception as e:
        logger.error("Token verification failed", error=str(e))
        raise APIException(
            ErrorCodes.INTERNAL_ERROR,
            "Token verification failed",
            500
        )

