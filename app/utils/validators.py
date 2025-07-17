"""
Comprehensive input validation system using Marshmallow.
Fixes the missing input validation issues identified in the review.
"""
from functools import wraps
from typing import Dict, Any, Optional

from flask import request
from marshmallow import Schema, fields, validate, ValidationError, post_load
import re

from app.utils.error_handlers import APIException, ErrorCodes


class BaseSchema(Schema):
    """Base schema with common validation methods."""
    
    @post_load
    def strip_strings(self, data, **kwargs):
        """Strip whitespace from string fields."""
        for key, value in data.items():
            if isinstance(value, str):
                data[key] = value.strip()
        return data


class EmailField(fields.Email):
    """Enhanced email field with additional validation."""
    
    def _validate(self, value, attr, data, **kwargs):
        super()._validate(value, attr, data, **kwargs)
        
        # Additional email validation
        if value:
            # Check for common disposable email domains
            disposable_domains = [
                '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
                'mailinator.com', 'throwaway.email'
            ]
            
            domain = value.split('@')[1].lower()
            if domain in disposable_domains:
                raise ValidationError("Disposable email addresses are not allowed")


class PasswordField(fields.String):
    """Password field with strength validation."""
    
    def _validate(self, value, attr, data, **kwargs):
        super()._validate(value, attr, data, **kwargs)
        
        if value:
            errors = []
            
            # Length check
            if len(value) < 8:
                errors.append("Password must be at least 8 characters long")
            
            # Character requirements
            if not re.search(r'[A-Z]', value):
                errors.append("Password must contain at least one uppercase letter")
            
            if not re.search(r'[a-z]', value):
                errors.append("Password must contain at least one lowercase letter")
            
            if not re.search(r'\d', value):
                errors.append("Password must contain at least one number")
            
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
                errors.append("Password must contain at least one special character")
            
            # Common password check
            common_passwords = [
                'password', '123456', 'password123', 'admin', 'qwerty',
                'letmein', 'welcome', 'monkey', '1234567890'
            ]
            
            if value.lower() in common_passwords:
                errors.append("Password is too common")
            
            if errors:
                raise ValidationError(errors)


class DomainField(fields.String):
    """Domain validation field."""
    
    def _validate(self, value, attr, data, **kwargs):
        super()._validate(value, attr, data, **kwargs)
        
        if value:
            # Remove protocol if present
            domain = value.replace('http://', '').replace('https://', '')
            domain = domain.split('/')[0]  # Remove path
            
            # Basic domain validation
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            
            if not domain_pattern.match(domain):
                raise ValidationError("Invalid domain format")


# Authentication Schemas
class UserRegistrationSchema(BaseSchema):
    """Schema for user registration validation."""
    
    email = EmailField(required=True)
    password = PasswordField(required=True)
    first_name = fields.Str(
        required=True, 
        validate=validate.Length(min=1, max=100),
        error_messages={'required': 'First name is required'}
    )
    last_name = fields.Str(
        required=True, 
        validate=validate.Length(min=1, max=100),
        error_messages={'required': 'Last name is required'}
    )
    company = fields.Str(
        validate=validate.Length(max=255),
        missing=None
    )


class UserLoginSchema(BaseSchema):
    """Schema for user login validation."""
    
    email = EmailField(required=True)
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1),
        error_messages={'required': 'Password is required'}
    )


class PasswordResetRequestSchema(BaseSchema):
    """Schema for password reset request."""
    
    email = EmailField(required=True)


class PasswordResetSchema(BaseSchema):
    """Schema for password reset."""
    
    token = fields.Str(required=True)
    new_password = PasswordField(required=True)


# Website Management Schemas
class WebsiteCreateSchema(BaseSchema):
    """Schema for website creation."""
    
    domain = DomainField(
        required=True,
        validate=validate.Length(min=3, max=255)
    )


class WebsiteUpdateSchema(BaseSchema):
    """Schema for website updates."""
    
    domain = DomainField(
        validate=validate.Length(min=3, max=255),
        missing=None
    )
    status = fields.Str(
        validate=validate.OneOf(['active', 'suspended', 'deleted']),
        missing=None
    )


# Analytics Schemas
class AnalyticsEventSchema(BaseSchema):
    """Schema for analytics event tracking."""
    
    client_id = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255)
    )
    event_type = fields.Str(
        required=True,
        validate=validate.OneOf([
            'page_view', 'consent_given', 'consent_denied', 
            'banner_shown', 'settings_opened'
        ])
    )
    visitor_id = fields.Str(
        validate=validate.Length(max=255),
        missing=None
    )
    consent_given = fields.Bool(missing=None)
    revenue_generated = fields.Decimal(
        validate=validate.Range(min=0),
        missing=0
    )
    metadata = fields.Dict(missing=dict)


class AnalyticsQuerySchema(BaseSchema):
    """Schema for analytics queries."""
    
    start_date = fields.Date(required=True)
    end_date = fields.Date(required=True)
    website_id = fields.Int(
        validate=validate.Range(min=1),
        missing=None
    )
    event_type = fields.Str(
        validate=validate.OneOf([
            'page_view', 'consent_given', 'consent_denied', 
            'banner_shown', 'settings_opened'
        ]),
        missing=None
    )


# Pagination Schema
class PaginationSchema(BaseSchema):
    """Schema for pagination parameters."""
    
    page = fields.Int(
        validate=validate.Range(min=1),
        missing=1
    )
    per_page = fields.Int(
        validate=validate.Range(min=1, max=100),
        missing=20
    )
    sort_by = fields.Str(
        validate=validate.OneOf([
            'created_at', 'updated_at', 'domain', 'status', 
            'visitors_today', 'revenue_today'
        ]),
        missing='created_at'
    )
    sort_order = fields.Str(
        validate=validate.OneOf(['asc', 'desc']),
        missing='desc'
    )


# Payment Schemas
class PaymentMethodSchema(BaseSchema):
    """Schema for payment method validation."""
    
    provider = fields.Str(
        required=True,
        validate=validate.OneOf(['stripe', 'paypal'])
    )
    account_id = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255)
    )


class PayoutRequestSchema(BaseSchema):
    """Schema for payout requests."""
    
    amount = fields.Decimal(
        required=True,
        validate=validate.Range(min=10)  # Minimum $10 payout
    )
    payout_method_id = fields.Int(
        required=True,
        validate=validate.Range(min=1)
    )


# Admin Schemas
class AdminUserUpdateSchema(BaseSchema):
    """Schema for admin user updates."""
    
    subscription_tier = fields.Str(
        validate=validate.OneOf(['free', 'basic', 'pro', 'enterprise']),
        missing=None
    )
    is_admin = fields.Bool(missing=None)
    status = fields.Str(
        validate=validate.OneOf(['active', 'suspended', 'deleted']),
        missing=None
    )


# Contact Form Schema
class ContactFormSchema(BaseSchema):
    """Schema for contact form validation."""
    
    name = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100)
    )
    email = EmailField(required=True)
    subject = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=200)
    )
    message = fields.Str(
        required=True,
        validate=validate.Length(min=10, max=2000)
    )


def validate_json(schema_class: Schema):
    """
    Decorator for validating JSON request data.
    
    Args:
        schema_class: Marshmallow schema class for validation
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get JSON data
                json_data = request.get_json()
                if json_data is None:
                    raise APIException(
                        ErrorCodes.VALIDATION_ERROR,
                        "Request must contain valid JSON",
                        400
                    )
                
                # Validate data
                schema = schema_class()
                validated_data = schema.load(json_data)
                
                # Pass validated data to the function
                return f(validated_data, *args, **kwargs)
                
            except ValidationError as err:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "Request validation failed",
                    422,
                    {"validation_errors": err.messages}
                )
            except APIException:
                raise
            except Exception as e:
                raise APIException(
                    ErrorCodes.INTERNAL_ERROR,
                    "Validation processing failed",
                    500
                )
        
        return decorated_function
    return decorator


def validate_query_params(schema_class: Schema):
    """
    Decorator for validating query parameters.
    
    Args:
        schema_class: Marshmallow schema class for validation
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get query parameters
                query_data = request.args.to_dict()
                
                # Validate data
                schema = schema_class()
                validated_data = schema.load(query_data)
                
                # Pass validated data to the function
                return f(validated_data, *args, **kwargs)
                
            except ValidationError as err:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "Query parameter validation failed",
                    400,
                    {"validation_errors": err.messages}
                )
            except APIException:
                raise
            except Exception as e:
                raise APIException(
                    ErrorCodes.INTERNAL_ERROR,
                    "Query validation processing failed",
                    500
                )
        
        return decorated_function
    return decorator


def sanitize_html(text: str) -> str:
    """Basic HTML sanitization for user input."""
    if not text:
        return text
    
    # Remove potentially dangerous HTML tags
    dangerous_tags = [
        '<script', '</script>', '<iframe', '</iframe>',
        '<object', '</object>', '<embed', '</embed>',
        '<form', '</form>', 'javascript:', 'vbscript:',
        'onload=', 'onerror=', 'onclick='
    ]
    
    sanitized = text
    for tag in dangerous_tags:
        sanitized = sanitized.replace(tag.lower(), '')
        sanitized = sanitized.replace(tag.upper(), '')
    
    return sanitized


def validate_file_upload(allowed_extensions: set, max_size: int = 5 * 1024 * 1024):
    """
    Decorator for validating file uploads.
    
    Args:
        allowed_extensions: Set of allowed file extensions
        max_size: Maximum file size in bytes (default 5MB)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'file' not in request.files:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "No file provided",
                    400
                )
            
            file = request.files['file']
            
            if file.filename == '':
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "No file selected",
                    400
                )
            
            # Check file extension
            if '.' not in file.filename:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    "File must have an extension",
                    400
                )
            
            extension = file.filename.rsplit('.', 1)[1].lower()
            if extension not in allowed_extensions:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}",
                    400
                )
            
            # Check file size
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning
            
            if file_size > max_size:
                raise APIException(
                    ErrorCodes.VALIDATION_ERROR,
                    f"File too large. Maximum size: {max_size // (1024*1024)}MB",
                    400
                )
            
            return f(file, *args, **kwargs)
        
        return decorated_function
    return decorator


def validate_url(url):
    """Validate URL format"""
    import re
    pattern = r'^https?://(?:[-\w.] )+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'
    return bool(re.match(pattern, url))
